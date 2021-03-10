#include "stream_client.h"

#include "adapters.h"
#include "datagram.h"
#include "debug.h"
#include "socket_utils.h"

#include <wil/result.h>

#include <iostream>
#include <fstream>

namespace multipath {
namespace {

    constexpr DWORD c_defaultSocketReceiveBufferSize = 1048576; // 1MB receive buffer

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

StreamClient::StreamClient(ctl::ctSockaddr targetAddress, unsigned long receiveBufferCount, HANDLE completeEvent) :
    m_targetAddress(std::move(targetAddress)), m_completeEvent(completeEvent), m_receiveBufferCount(receiveBufferCount)
{
    m_primaryState.m_socket.reset(CreateDatagramSocket());
    m_primaryState.m_interface = Interface::Primary;
    m_primaryState.m_interfaceIndex = 0;
    m_primaryState.m_adapterStatus = AdapterStatus::Ready;
    SetSocketReceiveBufferSize(m_primaryState.m_socket.get(), c_defaultSocketReceiveBufferSize);
    SetSocketOutgoingInterface(m_primaryState.m_socket.get(), m_targetAddress.family(), m_primaryState.m_interfaceIndex);

    PRINT_DEBUG_INFO(
        "\tStreamClient::StreamClient - created primary socket %zu bound to interface index %d\n",
        m_primaryState.m_socket.get(),
        m_primaryState.m_interfaceIndex);

    m_primaryState.m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_primaryState.m_socket.get());
    m_threadpoolTimer = std::make_unique<ThreadpoolTimer>([this]() noexcept { TimerCallback(); });

    // allocate the receive contexts
    m_primaryState.m_receiveStates.resize(m_receiveBufferCount);

    PRINT_DEBUG_INFO("\tStreamClient::Start - number of pre-posted receives is %lu\n", receiveBufferCount);

    // initialize the send buffer
    for (size_t i = 0u; i < m_sharedSendBuffer.size(); ++i)
    {
        m_sharedSendBuffer[i] = static_cast<char>(i);
    }
}

void StreamClient::RequestSecondaryWlanConnection()
{
    if (!m_wlanHandle)
    {
        // The handle to the wlan api must stay open to keep the secondary connection active
        m_wlanHandle = OpenWlanHandle();
        RequestSecondaryInterface(m_wlanHandle.get());
        PRINT_DEBUG_INFO("\tStreamClient::RequestSecondaryWlanConnection - Secondary wlan connection requested\n");
    }
}

void StreamClient::SetupSecondaryInterface()
{
    if (!m_wlanHandle)
    {
        PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Secondary wlan connection not requested\n");
        return;
    }

    // Callback to update the secondary interface state in response to network status events
    auto updateSecondaryInterfaceStatus = [this]() {
        PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Processing network changed event\n");
        // Check if the primary interface changed
        winrt::guid connectedInterfaceGuid = []() {
            try
            {
                return NetworkInformation::GetInternetConnectionProfile().NetworkAdapter().NetworkAdapterId();
            }
            catch (...)
            {
                return winrt::guid{};
            }
        }();

        // TODO: take the lock only when needed. Find a better lock maybe
        auto lock = m_secondaryState.m_lock.lock();
        // If the default internet ip interface changed, the secondary wlan interface status changes too
        if (connectedInterfaceGuid != m_primaryInterfaceGuid)
        {
            PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - The preferred primary interface changed\n");
            m_primaryInterfaceGuid = connectedInterfaceGuid;

            // If a secondary wlan interface was used for the previous primary, tear it down
            if (m_secondaryState.m_adapterStatus == AdapterStatus::Ready)
            {
                PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Removing the secondary interface\n");
                m_secondaryState.m_adapterStatus = AdapterStatus::Disabled;
                m_secondaryState.m_socket.reset();
                lock.reset();

                // Wait for the completion of all remaining overlapped IO
                m_secondaryState.m_threadpoolIo.reset();

                lock = m_secondaryState.m_lock.lock();
                m_secondaryInterfaceGuid = {};
                PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Secondary interface removed\n");
            }

            // If a secondary wlan interface is available for the new primary interface, get ready to use it
            if (auto secondaryGuid = GetSecondaryInterfaceGuid(m_wlanHandle.get(), m_primaryInterfaceGuid))
            {
                m_secondaryInterfaceGuid = *secondaryGuid;
                m_secondaryState.m_adapterStatus = AdapterStatus::Connecting;
                PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Connecting a secondary interface for the new primary interface\n");
            }
        }

        // Once the secondary interface has network connectivity, setup it up for sending data
        if (m_secondaryState.m_adapterStatus == AdapterStatus::Connecting && IsAdapterConnected(m_secondaryInterfaceGuid))
        {
            PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Secondary interface connected. Setting up a socket\n");
            m_secondaryState.m_socket.reset(CreateDatagramSocket());
            m_secondaryState.m_interface = Interface::Secondary;
            m_secondaryState.m_interfaceIndex = ConvertInterfaceGuidToIndex(m_secondaryInterfaceGuid);
            SetSocketReceiveBufferSize(m_secondaryState.m_socket.get(), c_defaultSocketReceiveBufferSize);
            SetSocketOutgoingInterface(m_secondaryState.m_socket.get(), m_targetAddress.family(), m_secondaryState.m_interfaceIndex);
            m_secondaryState.m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_secondaryState.m_socket.get());

            m_secondaryState.m_receiveStates.resize(m_receiveBufferCount);
            Connect(m_secondaryState);
            for (auto& receiveState : m_secondaryState.m_receiveStates)
            {
                InitiateReceive(m_secondaryState, receiveState);
            }

            // The secondary interface is ready to send data, the client can start using it
            m_secondaryState.m_adapterStatus = AdapterStatus::Ready;
            PRINT_DEBUG_INFO("\tStreamClient::SetupSecondaryInterface - Secondary interface ready for use\n");
        }
    };

    // Initial setup
    updateSecondaryInterfaceStatus();

    // Subscribe for network status updates
    m_networkInformationEventRevoker = NetworkInformation::NetworkStatusChanged(
        winrt::auto_revoke, [updateSecondaryInterfaceStatus = std::move(updateSecondaryInterfaceStatus)](const auto&) {
        updateSecondaryInterfaceStatus(); });
}

void StreamClient::Start(unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration)
{
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
    SetupSecondaryInterface();

    PRINT_DEBUG_INFO("\tStreamClient::Start - connected to the server\n");

    PRINT_DEBUG_INFO("\tStreamClient::Start - start posting receive buffers\n");
    // initiate receives before starting the send timer
    for (auto& receiveState : m_primaryState.m_receiveStates)
    {
        InitiateReceive(m_primaryState, receiveState);
    }

    if (m_secondaryState.m_adapterStatus == AdapterStatus::Ready)
    {
        for (auto& receiveState : m_secondaryState.m_receiveStates)
        {
            InitiateReceive(m_secondaryState, receiveState);
        }
    }

    // start sends
    PRINT_DEBUG_INFO("\tStreamClient::Start - scheduling timer callback\n");
    m_threadpoolTimer->Schedule(m_tickInterval);
}

void StreamClient::Stop()
{
    m_stopCalled = true;

    PRINT_DEBUG_INFO("\tStreamClient::Stop - canceling timer callback\n");
    m_threadpoolTimer->Stop();

    PRINT_DEBUG_INFO("\tStreamClient::Stop - canceling timer callback\n");
    m_networkInformationEventRevoker.revoke();

    PRINT_DEBUG_INFO("\tStreamClient::Stop - closing sockets\n");
    {
        auto primaryLock = m_primaryState.m_lock.lock();
        m_primaryState.m_socket.reset();
    }

    {
        auto secondaryLock = m_secondaryState.m_lock.lock();
        m_secondaryState.m_socket.reset();
    }

    m_primaryState.m_threadpoolIo.reset();
    m_secondaryState.m_threadpoolIo.reset();

    SetEvent(m_completeEvent);
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
        long long aggregatedLatency = MAXLONGLONG;
        if (stat.m_sequenceNumber > 0)
        {
            if (stat.m_primaryReceiveTimestamp >= 0)
            {
                const auto primaryLatencyMs =
                    ConvertHundredNanosToMillis(stat.m_primaryReceiveTimestamp - stat.m_primarySendTimestamp);
                primaryLatencyTotal += primaryLatencyMs;
                primaryLatencySamples += 1;
                aggregatedLatency = primaryLatencyMs;
            }
            else
            {
                primaryLostFrames += 1;
            }

            if (stat.m_secondaryReceiveTimestamp >= 0)
            {
                const auto secondaryLatencyMs =
                    ConvertHundredNanosToMillis(stat.m_secondaryReceiveTimestamp - stat.m_secondarySendTimestamp);
                secondaryLatencyTotal += secondaryLatencyMs;
                secondaryLatencySamples += 1;
                aggregatedLatency = min(aggregatedLatency, secondaryLatencyMs);
            }
            else
            {
                secondaryLostFrames += 1;
            }

            if (stat.m_secondaryReceiveTimestamp >= 0 || stat.m_primaryReceiveTimestamp >= 0)
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

    const auto primaryAverageLatency = (primaryLatencySamples > 0 ? primaryLatencyTotal / primaryLatencySamples : 0);
    const auto secondaryAverageLatency = (secondaryLatencySamples > 0 ? secondaryLatencyTotal / secondaryLatencySamples : 0);
    const auto aggregatedAverageLatency = (aggregatedLatencySamples > 0 ? aggregatedLatencyTotal / aggregatedLatencySamples : 0);
    const auto aggregatedSendFrames = max(m_primaryState.m_sentFrames, m_secondaryState.m_sentFrames);

    std::cout << '\n';
    std::cout << "Sent frames on primary interface: " << m_primaryState.m_sentFrames << '\n';
    std::cout << "Sent frames on secondary interface: " << m_secondaryState.m_sentFrames << '\n';

    std::cout << '\n';
    std::cout << "Received frames on primary interface: " << m_primaryState.m_receivedFrames << " ("
              << (m_primaryState.m_sentFrames > 0 ? m_primaryState.m_receivedFrames * 100 / m_primaryState.m_sentFrames : 0) << "%)\n";
    std::cout << "Received frames on secondary interface: " << m_secondaryState.m_receivedFrames << " ("
              << (m_secondaryState.m_sentFrames > 0 ? m_secondaryState.m_receivedFrames * 100 / m_secondaryState.m_sentFrames : 0) << "%)\n";

    std::cout << '\n';
    std::cout << "Average latency on primary interface: " << primaryAverageLatency << '\n';
    std::cout << "Average latency on secondary interface: " << secondaryAverageLatency << '\n';
    std::cout << "Average latency on combined interface: " << aggregatedAverageLatency << " ("
              << (primaryAverageLatency > 0 ? (aggregatedAverageLatency - primaryAverageLatency) * 100 / primaryAverageLatency : 0) << "% improvement over primary) \n";

    std::cout << '\n';
    std::cout << "Lost frames on primary interface: " << primaryLostFrames << " ("
              << (m_primaryState.m_sentFrames > 0 ? (primaryLostFrames * 100 / m_primaryState.m_sentFrames) : 0) << "%)\n";
    std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << " ("
              << (m_secondaryState.m_sentFrames > 0 ? (secondaryLostFrames * 100 / m_secondaryState.m_sentFrames) : 0) << "%)\n";
    std::cout << "Lost frames on both interface simultaneously: " << aggregatedLostFrames << " ("
              << (aggregatedSendFrames > 0 ? (aggregatedLostFrames * 100 / aggregatedSendFrames) : 0) << "%)\n";

    std::cout << '\n';
    std::cout << "Corrupt frames on primary interface: " << m_primaryState.m_corruptFrames << '\n';
    std::cout << "Corrupt frames on secondary interface: " << m_secondaryState.m_corruptFrames << '\n';
}

void StreamClient::DumpLatencyData(std::ofstream& file)
{
    // Add column header
    file << "Sequence number, Primary Send timestamp (100ns), Primary Echo timestamp (100ns), Primary Receive "
            "timestamp (100ns), "
         << "Secondary Send timestamp (100ns), Secondary Echo timestamp (100ns), Secondary Receive timestamp (100ns)\n";
    // Add raw timestamp data
    for (const auto& stat : m_latencyStatistics)
    {
        file << stat.m_sequenceNumber << ", ";
        file << stat.m_primarySendTimestamp << ", " << stat.m_primaryEchoTimestamp << ", " << stat.m_primaryReceiveTimestamp << ", ";
        file << stat.m_secondarySendTimestamp << ", " << stat.m_secondaryEchoTimestamp << ", " << stat.m_secondaryReceiveTimestamp;
        file << "\n";
    }
}

void StreamClient::Connect(SocketState& socketState)
{
    // Send a first datagram so our sockets become bound to their respective interface's IP addresses.
    // `WSAReceiveFrom` will fail before the first datagram is sent.
    constexpr long long startSequenceNumber = -1;
    DatagramSendRequest sendRequest{startSequenceNumber, m_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();

    PRINT_DEBUG_INFO(
        "\tStreamClient::Connect - sending start message on %s socket %zu - sending to %ws\n",
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get(),
        m_targetAddress.WriteCompleteAddress().c_str());

    DWORD bytesTransferred = 0;
    auto error = WSASendTo(
        socketState.m_socket.get(),
        buffers.data(),
        static_cast<DWORD>(buffers.size()),
        &bytesTransferred,
        0,
        m_targetAddress.sockaddr(),
        m_targetAddress.length(),
        nullptr,
        nullptr);

    if (SOCKET_ERROR == error)
    {
        FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSASendTo failed");
    }

    // since the server will echo this message back, wait for the answer.
    // this use a blocking call, it could block the program if the packet is lost
    int targetAddressLength = m_targetAddress.length();
    auto& receiveBuffer = socketState.m_receiveStates[0].m_buffer; // just use the first receive buffer

    WSABUF recvWsabuf{};
    recvWsabuf.buf = receiveBuffer.data();
    recvWsabuf.len = static_cast<ULONG>(receiveBuffer.size());

    PRINT_DEBUG_INFO(
        "\tStreamClient::Connect - listening from the answer from %ws\n", m_targetAddress.WriteCompleteAddress().c_str());

    DWORD flags = 0;
    error = WSARecvFrom(
        socketState.m_socket.get(), &recvWsabuf, 1, &bytesTransferred, &flags, m_targetAddress.sockaddr(), &targetAddressLength, nullptr, nullptr);
    if (SOCKET_ERROR == error)
    {
        FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSARecvFrom failed");
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

        Stop();
    }
}

void StreamClient::SendDatagrams() noexcept
{
    // TODO guhetier: Data race on m_stopCalled. We should wait for all the send callbacks when stopping
    if (m_stopCalled)
    {
        return;
    }

    SendDatagram(m_primaryState);

    if (m_secondaryState.m_adapterStatus == AdapterStatus::Ready)
    {
        SendDatagram(m_secondaryState);
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

    DatagramSendRequest sendRequest{m_sequenceNumber, m_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();
    const SendState sendState{m_sequenceNumber, sendRequest.GetQpc()};

    PRINT_DEBUG_INFO(
        "\tStreamClient::SendDatagram - sending sequence number %lld on %s socket %zu\n",
        m_sequenceNumber,
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get());

    auto callback = [this, &socketState, sendState](OVERLAPPED* ov) noexcept {
        try
        {
            auto lock = socketState.m_lock.lock();

            if (m_stopCalled || !socketState.m_socket.is_valid())
            {
                PRINT_DEBUG_INFO("StreamClient::SendDatagram - Shutting down or socket is no longer valid, ignoring send completion\n");
                return;
            }

            DWORD bytesTransmitted = 0;
            DWORD flags = 0;
            if (WSAGetOverlappedResult(socketState.m_socket.get(), ov, &bytesTransmitted, false, &flags))
            {
                SendCompletion(socketState, sendState);
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

    FAIL_FAST_IF_MSG(sendState.m_sequenceNumber > MAXSIZE_T, "FATAL: sequence number out of bounds of vector");
    auto& stat = m_latencyStatistics[static_cast<unsigned int>(sendState.m_sequenceNumber)];

    stat.m_sequenceNumber = sendState.m_sequenceNumber;
    if (socketState.m_interface == Interface::Primary)
    {
        stat.m_primarySendTimestamp = sendState.m_sendTimestamp;
    }
    else
    {
        stat.m_secondarySendTimestamp = sendState.m_sendTimestamp;
    }
}

void StreamClient::InitiateReceive(SocketState& socketState, ReceiveState& receiveState)
{
    auto lock = socketState.m_lock.lock();

    if (m_stopCalled || !socketState.m_socket.is_valid())
    {
        return;
    }

    DWORD flags = 0;

    WSABUF wsabuf;
    wsabuf.buf = receiveState.m_buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveState.m_buffer.size());

    auto callback = [this, &socketState, &receiveState](OVERLAPPED* ov) noexcept {
        receiveState.m_receiveTimestamp = SnapQpc();

        auto lock = socketState.m_lock.lock();

        if (m_stopCalled || !socketState.m_socket.is_valid())
        {
            PRINT_DEBUG_INFO("\tStreamClient::InitiateReceive [callback] - Shutting down or socket is no longer valid, "
                             "ignoring receive completion\n");
            return;
        }

        DWORD bytesTransferred = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(socketState.m_socket.get(), ov, &bytesTransferred, false, &flags))
        {
            const auto lastError = WSAGetLastError();
            FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSARecvFrom failed  : %u", lastError);
        }

        ReceiveCompletion(socketState, receiveState, bytesTransferred);

        InitiateReceive(socketState, receiveState);
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
        nullptr,
        nullptr,
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

    const auto& header = ParseDatagramHeader(receiveState.m_buffer.data());

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

    auto& stat = m_latencyStatistics[static_cast<size_t>(header.m_sequenceNumber)];
    if (socketState.m_interface == Interface::Primary)
    {
        stat.m_primarySendTimestamp = header.m_sendTimestamp;
        stat.m_primaryEchoTimestamp = header.m_echoTimestamp;
        stat.m_primaryReceiveTimestamp = receiveState.m_receiveTimestamp;
    }
    else
    {
        stat.m_secondarySendTimestamp = header.m_sendTimestamp;
        stat.m_secondaryEchoTimestamp = header.m_echoTimestamp;
        stat.m_secondaryReceiveTimestamp = receiveState.m_receiveTimestamp;
    }
}
catch (...)
{
    FAIL_FAST_CAUGHT_EXCEPTION_MSG("FATAL: Unhandled exception in receive completion callback");
}

} // namespace multipath