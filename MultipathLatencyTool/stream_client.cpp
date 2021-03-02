#include "stream_client.h"
#include "socket_utils.h"
#include "datagram.h"
#include "debug.h"

#include <wil/result.h>

#include <iostream>

namespace multipath {
namespace {
    // calculates the interval at which to set the timer callback to send data at the specified rate (in bits per second)
    constexpr long long CalculateTickInterval(long long bitRate, long long frameRate, unsigned long long datagramSize) noexcept
    {
        // bitRate -> bit/s, datagramSize -> byte, frameRate -> N/U
        // We look for the tick interval in 100 nanosecond
        const long long hundredNanoSecInSecond = 10'000'000LL; // hundred ns / s
        const long long byteRate = bitRate / 8; // byte/s
        return (datagramSize * frameRate * hundredNanoSecInSecond) / byteRate;
    }

    long long CalculateFinalSequenceNumber(long long duration, long long bitRate, unsigned long long datagramSize) noexcept
    {
        // duration ->s, bitRate -> bit/s, datagramSize -> byte, frameRate -> N/U
        // We look for total number of datagram to send
        const long long byteRate = bitRate / 8; // byte/s
        return (duration * byteRate) / datagramSize;
    }

} // namespace

StreamClient::StreamClient(ctl::ctSockaddr targetAddress, int primaryInterfaceIndex, int secondaryInterfaceIndex, HANDLE completeEvent) :
    m_targetAddress(std::move(targetAddress)), m_completeEvent(completeEvent)
{
    constexpr DWORD defaultSocketReceiveBufferSize = 1048576; // 1MB receive buffer

    m_primaryState.m_socket.reset(CreateDatagramSocket());
    m_primaryState.m_interface = Interface::Primary;
    m_primaryState.m_interfaceIndex = primaryInterfaceIndex;
    SetSocketReceiveBufferSize(m_primaryState.m_socket.get(), defaultSocketReceiveBufferSize);
    SetSocketOutgoingInterface(m_primaryState.m_socket.get(), m_targetAddress.family(), m_primaryState.m_interfaceIndex);

    PRINT_DEBUG_INFO(
        "\tStreamClient::StreamClient - created primary socket %zu bound to interface index %d\n",
        m_primaryState.m_socket.get(),
        m_primaryState.m_interfaceIndex);

    m_primaryState.m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_primaryState.m_socket.get());

    m_secondaryState.m_socket.reset(CreateDatagramSocket());
    m_secondaryState.m_interface = Interface::Secondary;
    m_secondaryState.m_interfaceIndex = secondaryInterfaceIndex;
    SetSocketReceiveBufferSize(m_secondaryState.m_socket.get(), defaultSocketReceiveBufferSize);
    SetSocketOutgoingInterface(m_secondaryState.m_socket.get(), m_targetAddress.family(), m_secondaryState.m_interfaceIndex);

    PRINT_DEBUG_INFO(
        "\tStreamClient::StreamClient - created secondary socket %zu on bound to interface index %d\n",
        m_secondaryState.m_socket.get(),
        m_secondaryState.m_interfaceIndex);

    m_secondaryState.m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_secondaryState.m_socket.get());

    m_threadpoolTimer = std::make_unique<ThreadpoolTimer>([this]() noexcept { TimerCallback(); });
}

void StreamClient::Start(unsigned long receiveBufferCount, unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration)
{
    PRINT_DEBUG_INFO("\tStreamClient::Start - number of pre-posted receives is %lu\n", receiveBufferCount);

    // allocate our receive contexts
    m_primaryState.m_receiveStates.resize(receiveBufferCount);
    m_secondaryState.m_receiveStates.resize(receiveBufferCount);

    // initialize our send buffer
    for (size_t i = 0u; i < c_sendBufferSize / 2; ++i)
    {
        *reinterpret_cast<unsigned short*>(&m_sharedSendBuffer[i * 2]) = static_cast<unsigned short>(i);
    }

    m_frameRate = sendFrameRate;
    const auto tickInterval = CalculateTickInterval(sendBitRate, sendFrameRate, c_sendBufferSize);
    m_tickInterval = ConvertHundredNanosToRelativeFiletime(tickInterval);
    m_finalSequenceNumber = CalculateFinalSequenceNumber(duration, sendBitRate, c_sendBufferSize);

    PRINT_DEBUG_INFO("\tStreamClient::Start - tick interval is %lld\n", tickInterval);
    PRINT_DEBUG_INFO("\tStreamClient::Start - final sequence number is %lld\n", m_finalSequenceNumber);

    // allocate statistics buffer
    FAIL_FAST_IF_MSG(m_finalSequenceNumber > MAXSIZE_T, "Final sequence number exceeds limit of vector storage");
    m_latencyStatistics.resize(static_cast<size_t>(m_finalSequenceNumber));

    // connect to target on both sockets
    PRINT_DEBUG_INFO("\tStreamClient::Start - initiating connect on both sockets\n");
    Connect(m_primaryState);
    Connect(m_secondaryState);

    bool initiateIo = false;

    const HANDLE events[2] = {m_primaryState.m_connectEvent.get(), m_secondaryState.m_connectEvent.get()};
    const auto result = WaitForMultipleObjects(2, events, true, 2000); // 2 second delay for connect to complete
    switch (result)
    {
    case WAIT_OBJECT_0:
        [[fallthrough]];
    case WAIT_OBJECT_0 + 1:
        initiateIo = true;
        break;

    case WAIT_TIMEOUT:
        THROW_WIN32_MSG(ERROR_TIMEOUT, "Timed out waiting for connect to complete on both sockets");

    default:
        FAIL_FAST_WIN32_MSG(GetLastError(), "WaitForMultipleObjects failed");
    }

    if (initiateIo)
    {
        PRINT_DEBUG_INFO("\tStreamClient::Start - connected on both sockets\n");

        PRINT_DEBUG_INFO("\tStreamClient::Start - start posting receives\n");
        // initiate receives before starting the send timer
        for (auto& receiveState : m_primaryState.m_receiveStates)
        {
            InitiateReceive(m_primaryState, receiveState);
        }
        for (auto& receiveState : m_secondaryState.m_receiveStates)
        {
            InitiateReceive(m_secondaryState, receiveState);
        }

        // start sends
        PRINT_DEBUG_INFO("\tStreamClient::Start - scheduling timer callback\n");
        m_threadpoolTimer->Schedule(m_tickInterval);
    }
}

void StreamClient::Stop()
{
    m_stopCalled = true;

    PRINT_DEBUG_INFO("\tStreamClient::Stop - canceling timer callback\n");
    m_threadpoolTimer->Stop();

    PRINT_DEBUG_INFO("\tStreamClient::Stop - closing sockets\n");
    auto primaryLock = m_primaryState.m_lock.lock();
    m_primaryState.m_socket.reset();

    auto secondaryLock = m_secondaryState.m_lock.lock();
    m_secondaryState.m_socket.reset();
}

void StreamClient::PrintStatistics()
{
    // simple average of latencies for received datagrams
    long long primaryLatencyTotal = 0;
    long long secondaryLatencyTotal = 0;
    long long aggregatedLatencyTotal = 0;

    long long primaryLatencySamples = 0;
    long long secondaryLatencySamples = 0;
    long long aggregatedLatencySamples = 0;

    long long primaryLostFrames = 0;
    long long secondaryLostFrames = 0;
    long long aggregatedLostFrames = 0;

    for (const auto& stat : m_latencyStatistics)
    {
        long long aggregatedLatency = 0;
        if (stat.m_sequenceNumber > 0)
        {
            if (stat.m_primaryLatencyMs >= 0)
            {
                primaryLatencyTotal += stat.m_primaryLatencyMs;
                primaryLatencySamples += 1;
                aggregatedLatency = stat.m_primaryLatencyMs;
            }
            else
            {
                primaryLostFrames += 1;
            }

            if (stat.m_secondaryLatencyMs >= 0)
            {
                secondaryLatencyTotal += stat.m_secondaryLatencyMs;
                secondaryLatencySamples += 1;
                aggregatedLatency = min(aggregatedLatency, stat.m_primaryLatencyMs);
            }
            else
            {
                secondaryLostFrames += 1;
            }

            if (aggregatedLatency >= 0)
            {
                aggregatedLatencyTotal += aggregatedLatency;
                aggregatedLatencySamples += 1;
            }
            else
            {
                aggregatedLostFrames += 1;
            }
        }
    }

    std::cout << '\n';
    std::cout << "Sent frames on primary interface: " << m_primaryState.m_sentFrames << '\n';
    std::cout << "Sent frames on secondary interface: " << m_secondaryState.m_sentFrames << '\n';

    std::cout << '\n';
    std::cout << "Received frames on primary interface: " << m_primaryState.m_receivedFrames << '\n';
    std::cout << "Received frames on secondary interface: " << m_secondaryState.m_receivedFrames << '\n';

    std::cout << '\n';
    std::cout << "Average latency on primary interface: " << (primaryLatencySamples > 0 ? primaryLatencyTotal / primaryLatencySamples : 0) << '\n';
    std::cout << "Average latency on secondary interface: " << (secondaryLatencySamples > 0 ? secondaryLatencyTotal / secondaryLatencySamples : 0) << '\n';
    std::cout << "Average latency on combined interface: " << (secondaryLatencySamples > 0 ? aggregatedLatencyTotal / aggregatedLatencySamples : 0) << '\n';

    std::cout << '\n';
    std::cout << "Lost frames on primary interface: " << primaryLostFrames << '\n';
    std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << '\n';
    std::cout << "Lost frames on both interface simultaneously: " << aggregatedLostFrames << '\n';

    std::cout << '\n';
    std::cout << "Corrupt frames on primary interface: " << m_primaryState.m_corruptFrames << '\n';
    std::cout << "Corrupt frames on secondary interface: " << m_secondaryState.m_corruptFrames << '\n';
}

void StreamClient::Connect(SocketState& socketState)
{
    // simulate a connect call so that our sockets become bound to their respective interface's IP addresses

    // start message
    WSABUF wsabuf{};
    wsabuf.buf = const_cast<char*>(c_startMessage);
    wsabuf.len = c_startMessageLength;

    PRINT_DEBUG_INFO(
        "\tStreamClient::Connect - sending start message on %s socket %zu - sending to %ws\n",
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get(),
        m_targetAddress.WriteCompleteAddress().c_str());

    DWORD bytesTransferred = 0;
    auto error = WSASendTo(
        socketState.m_socket.get(), &wsabuf, 1, &bytesTransferred, 0, m_targetAddress.sockaddr(), m_targetAddress.length(), nullptr, nullptr);
    if (SOCKET_ERROR == error)
    {
        THROW_WIN32_MSG(WSAGetLastError(), "WSASendTo failed");
    }

    // since the server will echo this message back, we also post a receive to confirm the connection and discard the response

    int targetAddressLength = m_targetAddress.length();

    auto& receiveBuffer = socketState.m_receiveStates[0].m_buffer; // just use the first receive buffer

    WSABUF recvWsabuf{};
    recvWsabuf.buf = receiveBuffer.data();
    recvWsabuf.len = static_cast<ULONG>(receiveBuffer.size());

    OVERLAPPED* ov = socketState.m_threadpoolIo->new_request([this, &_socketState = socketState](OVERLAPPED* ov) noexcept {
        DWORD bytesTransferred = 0; // unused
        DWORD flags = 0; // unused
        if (!WSAGetOverlappedResult(_socketState.m_socket.get(), ov, &bytesTransferred, FALSE, &flags))
        {
            const auto gle = WSAGetLastError();
            FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSARecvFrom failed : %u", gle);
        }

        _socketState.m_connectEvent.SetEvent();

        PRINT_DEBUG_INFO(
            "\tStreamClient::Connect [callback] - successfully received echo'd start message on %s socket %zu\n",
            _socketState.m_interface == Interface::Primary ? "primary" : "secondary",
            _socketState.m_socket.get());
    });

    DWORD flags = 0;
    error = WSARecvFrom(
        socketState.m_socket.get(), &recvWsabuf, 1, nullptr, &flags, m_targetAddress.sockaddr(), &targetAddressLength, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "WSARecvFrom failed");
        }
    }
}

void StreamClient::TimerCallback() noexcept
{
    PRINT_DEBUG_INFO("\tStreamClient::TimerCallback - timer triggered\n");

    for (auto i = 0; i < m_frameRate && m_sequenceNumber < m_finalSequenceNumber; ++i)
    {
        SendDatagrams();
    }

    // requeue the timer
    if (m_sequenceNumber < m_finalSequenceNumber)
    {
        PRINT_DEBUG_INFO("\tStreamClient::TimerCallback - rescheduling timer\n");
        m_threadpoolTimer->Schedule(m_tickInterval);
    }
    else
    {
        PRINT_DEBUG_INFO("\tStreamClient::TimerCallback - final sequence number sent, canceling timer callback\n");

        FAIL_FAST_IF_MSG(m_sequenceNumber > m_finalSequenceNumber, "FATAL: Exceeded the expected number of packets sent");

        m_threadpoolTimer->Stop();

        SetEvent(m_completeEvent);
    }
}

void StreamClient::SendDatagrams() noexcept
{
    if (m_stopCalled)
    {
        return;
    }

    if (m_whichFirst == Interface::Primary)
    {
        SendDatagram(m_primaryState);
        SendDatagram(m_secondaryState);
        m_whichFirst = Interface::Secondary;
    }
    else
    {
        SendDatagram(m_secondaryState);
        SendDatagram(m_primaryState);
        m_whichFirst = Interface::Primary;
    }

    m_sequenceNumber += 1;
}

void StreamClient::SendDatagram(SocketState& socketState) noexcept
{
    auto lock = socketState.m_lock.lock();
    if (!socketState.m_socket.is_valid())
    {
        PRINT_DEBUG_INFO("\tStreamClient::SendDatagram - invalid socket, ignoring send request\n");
        return;
    }

    DatagramSendRequest sendRequest{m_sequenceNumber, m_sharedSendBuffer.data(), m_sharedSendBuffer.size()};

    auto& buffers = sendRequest.GetBuffers();

    const SendState sendState{m_sequenceNumber, sendRequest.GetQpc()};

    PRINT_DEBUG_INFO(
        "\tStreamClient::SendDatagram - sending sequence number %lld on %s socket %zu\n",
        m_sequenceNumber,
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get());

    auto callback = [this, &_socketState = socketState, _sendState = sendState](OVERLAPPED* ov) noexcept {
        try
        {
            auto lock = _socketState.m_lock.lock();

            if (m_stopCalled || !_socketState.m_socket.is_valid())
            {
                PRINT_DEBUG_INFO("StreamClient::SendDatagram - Shutting down or socket is no longer valid, ignoring send completion\n");
                return;
            }

            DWORD bytesTransmitted = 0;
            DWORD flags = 0;
            if (WSAGetOverlappedResult(_socketState.m_socket.get(), ov, &bytesTransmitted, FALSE, &flags))
            {
                SendCompletion(_socketState, _sendState);
            }
            else
            {
                const auto gle = WSAGetLastError();
                PRINT_DEBUG_INFO("StreamClient::SendDatagram - WSASendTo failed : %u\n", gle);
            }
        }
        catch (...)
        {
            FAIL_FAST_CAUGHT_EXCEPTION_MSG("FATAL: Unhandled exception in send completion callback");
        }
    };

    OVERLAPPED* ov = socketState.m_threadpoolIo->new_request(callback);

    auto error = WSASendTo(
        socketState.m_socket.get(),
        buffers.data(),
        static_cast<DWORD>(buffers.size()),
        nullptr,
        0,
        m_targetAddress.sockaddr(),
        m_targetAddress.length(),
        ov,
        nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            socketState.m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "WSASendTo failed");
        }
    }
}

void StreamClient::SendCompletion(SocketState& socketState, const SendState& sendState) noexcept
{
    socketState.m_sentFrames += 1;

    FAIL_FAST_IF_MSG(sendState.m_sequenceNumber > MAXSIZE_T, "FATAL: received sequence number out of bounds of vector");
    auto& stat = m_latencyStatistics[static_cast<unsigned int>(sendState.m_sequenceNumber)];

    stat.m_sequenceNumber = sendState.m_sequenceNumber;
    if (socketState.m_interface == Interface::Primary)
    {
        stat.m_primarySendQpc = sendState.m_qpc;
    }
    else
    {
        stat.m_secondarySendQpc = sendState.m_qpc;
    }
}

void StreamClient::InitiateReceive(SocketState& socketState, ReceiveState& receiveState)
{
    auto lock = socketState.m_lock.lock();

    if (m_stopCalled || !socketState.m_socket.is_valid())
    {
        return;
    }

    receiveState.m_remoteAddressLen = receiveState.m_remoteAddress.length();

    DWORD flags = 0;

    WSABUF wsabuf;
    wsabuf.buf = receiveState.m_buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveState.m_buffer.size());

    auto callback = [this, &_socketState = socketState, &_receiveState = receiveState](OVERLAPPED* ov) noexcept {
        _receiveState.m_qpc = SnapQpc();

        auto lock = _socketState.m_lock.lock();

        if (m_stopCalled || !_socketState.m_socket.is_valid())
        {
            PRINT_DEBUG_INFO("\tStreamClient::InitiateReceive [callback] - Shutting down or socket is no longer valid, "
                             "ignoring receive completion\n");
            return;
        }

        DWORD bytesTransferred = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(_socketState.m_socket.get(), ov, &bytesTransferred, FALSE, &flags))
        {
            const auto gle = WSAGetLastError();
            FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSARecvFrom failed  : %u", gle);
        }

        ReceiveCompletion(_socketState, _receiveState, bytesTransferred);

        InitiateReceive(_socketState, _receiveState);
    };

    DWORD bytesTransferred = 0;
    OVERLAPPED* ov = socketState.m_threadpoolIo->new_request(callback);

    PRINT_DEBUG_INFO(
        "\tStreamClient::InitiateReceive - initiating WSARecvFrom on socket %zu\n",
        socketState.m_socket.get());

    auto error = WSARecvFrom(
        socketState.m_socket.get(),
        &wsabuf,
        1,
        &bytesTransferred,
        &flags,
        receiveState.m_remoteAddress.sockaddr(),
        &receiveState.m_remoteAddressLen,
        ov,
        nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            socketState.m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "WSARecvFrom failed");
        }
    }
}

void StreamClient::ReceiveCompletion(SocketState& socketState, ReceiveState& receiveState, DWORD messageSize) noexcept
try
{
    FAIL_FAST_IF_MSG(!ValidateBufferLength(receiveState.m_buffer.data(), receiveState.m_buffer.size(), messageSize), "Received invalid message");

    const auto header = ExtractDatagramHeaderFromBuffer(receiveState.m_buffer.data(), messageSize);

    PRINT_DEBUG_INFO(
        "\tStreamClient::ReceiveCompletion - received sequence number %lld on %s socket %zu\n",
        header.m_sequenceNumber,
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get());

    if (header.m_sequenceNumber < 0 || header.m_sequenceNumber >= m_finalSequenceNumber)
    {
        PRINT_DEBUG_INFO("\tStreamClient::ReceiveCompletion - received corrupt frame\n");

        socketState.m_corruptFrames += 1;
        return;
    }

    socketState.m_receivedFrames += 1;

    FAIL_FAST_IF_MSG(header.m_sequenceNumber > MAXSIZE_T, "FATAL: received sequence number out of bounds of vector");
    auto& stat = m_latencyStatistics[static_cast<size_t>(header.m_sequenceNumber)];

    if (socketState.m_interface == Interface::Primary)
    {
        stat.m_primaryLatencyMs = ConvertHundredNanosToMillis(receiveState.m_qpc - header.m_qpc);
    }
    else
    {
        stat.m_secondaryLatencyMs = ConvertHundredNanosToMillis(receiveState.m_qpc - header.m_qpc);
    }
}
catch (...)
{
    FAIL_FAST_CAUGHT_EXCEPTION_MSG("FATAL: Unhandled exception in receive completion callback");
}

} // namespace multipath