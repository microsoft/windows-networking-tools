#include "pch.h"

#include "stream_client.h"
#include "socket_utils.h"
#include "datagram.h"

#include <wil/result.h>

namespace multipath {
namespace {
    // calculates the interval at which to set the timer callback to send data at the specified rate (in bits per second)
    long long CalculateTickInterval(long long bitRate, unsigned long long datagramSize) noexcept
    {
        const long long byteRate = bitRate / 8;
        const long long datagramRate = byteRate * 60 / static_cast<long long>(datagramSize);

        // now we need to determine how often the timer should tick (in 100 nanos increments)
        long long interval = 1'000'000LL;
        FAIL_FAST_IF_MSG(datagramRate > interval, "datagram send rate higher than the available tick interval");

        return static_cast<long long>(interval / datagramRate);
    }

    long long CalculateFinalSequenceNumber(long long duration, long long bitRate, unsigned long long datagramSize) noexcept
    {
        const long long byteRate = bitRate / 8;
        const long long datagramRate = byteRate * 60 / static_cast<long long>(datagramSize);

        return static_cast<long long>(datagramRate * duration);
    }

} // namespace

StreamClient::StreamClient(const Sockaddr& _targetAddress, int _primaryInterfaceIndex, int _secondaryInterfaceIndex, HANDLE _completeEvent) :
    m_targetAddress(_targetAddress), m_completeEvent(_completeEvent)
{
    constexpr DWORD DefaultSocketReceiveBufferSize = 1048576; // 1MB receive buffer

    m_primaryState.socket.reset(CreateDatagramSocket());
    m_primaryState.interface = Interface::Primary;
    m_primaryState.interfaceIndex = _primaryInterfaceIndex;
    SetSocketReceiveBufferSize(m_primaryState.socket.get(), DefaultSocketReceiveBufferSize);
    // SetSocketOutgoingInterface(m_primaryState.socket.get(), m_targetAddress.family(), m_primaryState.interfaceIndex);

    m_primaryState.connectEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!m_primaryState.connectEvent)
    {
        THROW_WIN32_MSG(GetLastError(), "CreateEvent (primary) failed");
    }

    m_primaryState.threadpoolIo = std::make_unique<ThreadpoolIo>(m_primaryState.socket.get());

    m_secondaryState.socket.reset(CreateDatagramSocket());
    m_secondaryState.interface = Interface::Secondary;
    m_secondaryState.interfaceIndex = _secondaryInterfaceIndex;
    SetSocketReceiveBufferSize(m_secondaryState.socket.get(), DefaultSocketReceiveBufferSize);
    SetSocketOutgoingInterface(m_secondaryState.socket.get(), m_targetAddress.family(), m_secondaryState.interfaceIndex);

    m_secondaryState.connectEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!m_secondaryState.connectEvent)
    {
        THROW_WIN32_MSG(GetLastError(), "CreateEvent (secondary) failed");
    }

    m_secondaryState.threadpoolIo = std::make_unique<ThreadpoolIo>(m_secondaryState.socket.get());

    m_threadpoolTimer = std::make_unique<ThreadpoolTimer>([this]() noexcept { TimerCallback(); });
}

StreamClient::~StreamClient()
{
}

void StreamClient::Start(unsigned long prePostRecvs, unsigned long sendBitRate, unsigned long duration)
{
    // allocate our receive contexts
    m_primaryState.receiveStates.resize(prePostRecvs);
    m_secondaryState.receiveStates.resize(prePostRecvs);

    // initialize our send buffer
    for (size_t i = 0u; i < SendBufferSize / 2; ++i)
    {
        *reinterpret_cast<unsigned short*>(&m_sharedSendBuffer[i * 2]) = static_cast<unsigned short>(i);
    }

    m_tickInterval = ConvertHundredNanosToRelativeFiletime(CalculateTickInterval(sendBitRate, SendBufferSize));
    m_finalSequenceNumber = CalculateFinalSequenceNumber(duration, sendBitRate, SendBufferSize);

    // allocate statistics buffer
    m_latencyStatistics.resize(m_finalSequenceNumber);

    // connect to target on both sockets
    Connect(m_primaryState);
    Connect(m_secondaryState);

    bool initiateIo = false;

    HANDLE events[2] = {m_primaryState.connectEvent, m_secondaryState.connectEvent};
    auto result = WaitForMultipleObjects(2, events, TRUE, 10000); // 1 second delay for connect to complete
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
        // initiate receives before starting the send timer
        for (auto& receiveState : m_primaryState.receiveStates)
        {
            InitiateReceive(m_primaryState, receiveState);
        }
        for (auto& receiveState : m_secondaryState.receiveStates)
        {
            InitiateReceive(m_secondaryState, receiveState);
        }

        // start sends
        m_threadpoolTimer->Schedule(m_tickInterval);
    }
}

void StreamClient::Stop()
{
    // close the sockets before cancelling the timer callbacks
    m_primaryState.socket.reset();
    m_secondaryState.socket.reset();

    m_threadpoolTimer->Stop();
}

void StreamClient::PrintStatistics()
{
    // simple average of latencies for received datagrams
    long long primaryLatencyTotal = 0;
    long long secondaryLatencyTotal = 0;

    long long primaryLatencySamples = 0;
    long long secondaryLatencySamples = 0;

    long long primaryLostFrames = 0;
    long long secondaryLostFrames = 0;

    for (auto i = 0u; i < m_latencyStatistics.size(); ++i)
    {
        auto const& stat = m_latencyStatistics[i];
        if (stat.sequenceNumber > 0)
        {
            if (stat.primaryLatencyMs > 0)
            {
                primaryLatencyTotal += stat.primaryLatencyMs;
                primaryLatencySamples += 1;
            }
            else
            {
                primaryLostFrames += 1;
            }

            if (stat.secondaryLatencyMs > 0)
            {
                secondaryLatencyTotal += stat.secondaryLatencyMs;
                secondaryLatencySamples += 1;
            }
        }
        else
        {
            secondaryLostFrames += 1;
        }
    }

    std::cout << '\n';
    std::cout << "Average latency on primary interface: " << primaryLatencyTotal / primaryLatencySamples << '\n';
    std::cout << "Average latency on secondary interface: " << secondaryLatencyTotal / secondaryLatencySamples << '\n';

    std::cout << '\n';
    std::cout << "Lost frames on primary interface: " << primaryLostFrames << '\n';
    std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << '\n';
}

void StreamClient::Connect(SocketState& socketState)
{
    // simulate a connect call so that our sockets become bound to their respective interface's IP addresses

    // start message
    WSABUF wsabuf{};
    wsabuf.buf = const_cast<char*>(START_MESSAGE);
    wsabuf.len = START_MESSAGE_LENGTH;

    auto callback = [this, &_socketState = socketState](OVERLAPPED* ov) noexcept {
        DWORD bytesTransferred = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesTransferred, FALSE, &flags))
        {
            FAIL_FAST_WIN32_MSG(WSAGetLastError(), "Failed to send connect request");
        }
    };

    OVERLAPPED* ov = socketState.threadpoolIo->NewRequest(callback);

    auto error = WSASendTo(
        socketState.socket.get(), &wsabuf, 1, nullptr, 0, m_targetAddress.sockaddr(), m_targetAddress.length(), ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            socketState.threadpoolIo->CancelRequest(ov);
            THROW_WIN32_MSG(error, "Failed to send connect request");
        }

        error = NO_ERROR;
    }

    if (NO_ERROR == error)
    {
        static int targetAddressLength = m_targetAddress.length();

        // since the server will echo this message back, we also post a receive to discard the message
        char buffer[32] = {};

        WSABUF recvWsabuf{};
        recvWsabuf.buf = buffer;
        recvWsabuf.len = sizeof(buffer);

        auto recvCallback = [&_socketState = socketState](OVERLAPPED* ov) noexcept {
            DWORD bytesTransferred = 0;
            DWORD flags = 0;
            if (!WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesTransferred, FALSE, &flags))
            {
                FAIL_FAST_WIN32_MSG(WSAGetLastError(), "Failed to receive connect response");
            }

            if (!SetEvent(_socketState.connectEvent))
            {
                FAIL_FAST_WIN32_MSG(GetLastError(), "SetEvent failed");
            }
        };

        OVERLAPPED* recvOv = socketState.threadpoolIo->NewRequest(recvCallback);

        DWORD flags = 0;
        error = WSARecvFrom(
            socketState.socket.get(), &recvWsabuf, 1, nullptr, &flags, m_targetAddress.sockaddr(), &targetAddressLength, recvOv, nullptr);
        if (SOCKET_ERROR == error)
        {
            error = WSAGetLastError();
            if (WSA_IO_PENDING != error)
            {
                socketState.threadpoolIo->CancelRequest(recvOv);
                THROW_WIN32_MSG(error, "Failed to receive connect response");
            }
        }
        else
        {
            // IO completed inline
            if (!SetEvent(socketState.connectEvent))
            {
                FAIL_FAST_WIN32_MSG(GetLastError(), "SetEvent failed");
            }
        }
    }
}

void StreamClient::TimerCallback() noexcept
{
    for (auto i = 0; i < 60; ++i)
    {
        SendDatagrams();
    }

    // requeue the timer
    if (m_sequenceNumber < m_finalSequenceNumber)
    {
        m_threadpoolTimer->Schedule(m_tickInterval);
    }
    else
    {
        m_threadpoolTimer->Stop();

        SetEvent(m_completeEvent);
    }
}

void StreamClient::SendDatagrams()
{
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

void StreamClient::SendDatagram(SocketState& socketState)
{
    DatagramSendRequest sendRequest{
        m_sequenceNumber, socketState.interfaceIndex, m_sharedSendBuffer.data(), m_sharedSendBuffer.size()};

    auto& buffers = sendRequest.GetBuffers();

    SendState sendState{m_sequenceNumber, sendRequest.GetQpc()};

    auto callback = [this, &_socketState = socketState, _sendState = sendState](OVERLAPPED* ov) noexcept {
        DWORD bytesTransmitted = 0;
        DWORD flags = 0;
        if (WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesTransmitted, FALSE, &flags))
        {
            auto& stat = m_latencyStatistics[_sendState.sequenceNumber];

            stat.sequenceNumber = _sendState.sequenceNumber;
            if (_socketState.interface == Interface::Primary)
            {
                stat.primarySendQpc = _sendState.qpc;
            }
            else
            {
                stat.secondarySendQpc = _sendState.qpc;
            }
        }
    };

    OVERLAPPED* ov = socketState.threadpoolIo->NewRequest(callback);
    DWORD bytesTransferred = 0;

    auto error = WSASendTo(
        socketState.socket.get(),
        buffers.data(),
        static_cast<DWORD>(buffers.size()),
        &bytesTransferred,
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
            socketState.threadpoolIo->CancelRequest(ov);
            FAILED_WIN32_LOG(error);

            // record that the send failed by using a negative timestamp
        }
    }
    else
    {
        // save the sent
    }
}

void StreamClient::InitiateReceive(SocketState& socketState, ReceiveState& receiveState)
{
    receiveState.remoteAddressLen = receiveState.remoteAddress.length();

    DWORD flags = 0;

    WSABUF wsabuf;
    wsabuf.buf = receiveState.buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveState.buffer.size());

    auto callback = [this, &_socketState = socketState, &_receiveState = receiveState](OVERLAPPED* ov) noexcept {
        // snap QPC on entry
        LARGE_INTEGER qpc{};
        QueryPerformanceCounter(&qpc);

        DWORD bytesReceived = 0;
        DWORD flags = 0;
        if (WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesReceived, FALSE, &flags))
        {
            auto header = ExtractDatagramHeaderFromBuffer(_receiveState.buffer.data(), _receiveState.buffer.size());

            if (header.sequenceNumber < 0 || header.sequenceNumber >= m_finalSequenceNumber)
            {
                _socketState.corruptFrames += 1;
                return;
            }

            auto& stat = m_latencyStatistics[header.sequenceNumber];

            if (_socketState.interface == Interface::Primary)
            {
                stat.primaryLatencyMs = ConvertHundredNanosToMillis(qpc.QuadPart - header.qpc.QuadPart);
            }
            else
            {
                stat.secondaryLatencyMs = ConvertHundredNanosToMillis(qpc.QuadPart - header.qpc.QuadPart);
            }
        }

        InitiateReceive(_socketState, _receiveState);
    };

    OVERLAPPED* ov = socketState.threadpoolIo->NewRequest(callback);

    auto error = WSARecvFrom(
        socketState.socket.get(), &wsabuf, 1, nullptr, &flags, receiveState.remoteAddress.sockaddr(), &receiveState.remoteAddressLen, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            socketState.threadpoolIo->CancelRequest(ov);
            FAILED_WIN32_LOG(error);
        }
    }
}

} // namespace multipath