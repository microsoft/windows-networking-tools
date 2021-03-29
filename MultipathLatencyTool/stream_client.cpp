#include "stream_client.h"

#include "adapters.h"
#include "datagram.h"
#include "logs.h"
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
        const long long byteRate = bitRate / 8;                // byte/s
        return (datagramSize * frameRate * hundredNanoSecInSecond) / byteRate;
    }

    long long CalculateNumberOfDatagramToSend(long long duration, long long bitRate, unsigned long long datagramSize) noexcept
    {
        // duration ->s, bitRate -> bit/s, datagramSize -> byte, frameRate -> N/U
        // We look for total number of datagram to send
        const long long byteRate = bitRate / 8; // byte/s
        return (duration * byteRate) / datagramSize;
    }

} // namespace

StreamClient::SocketState::SocketState(Interface interface) : m_interface{interface}
{
}

StreamClient::SocketState ::~SocketState() noexcept
{
    // guarantee the socket is torn down and all callbacks are completed before freeing member buffers
    Cancel();
}

void StreamClient::SocketState::Setup(const ctl::ctSockaddr& targetAddress, int numReceivedBuffers, int interfaceIndex)
{
    m_socket.reset(CreateDatagramSocket());
    SetSocketReceiveBufferSize(m_socket.get(), c_defaultSocketReceiveBufferSize);
    SetSocketOutgoingInterface(m_socket.get(), targetAddress.family(), interfaceIndex);
    m_receiveStates.resize(numReceivedBuffers);

    auto error = WSAConnect(m_socket.get(), targetAddress.sockaddr(), targetAddress.length(), nullptr, nullptr, nullptr, nullptr);
    if (SOCKET_ERROR == error)
    {
        FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSAConnect failed");
    }

    m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_socket.get());
}

void StreamClient::SocketState::Cancel()
{
    // Ensure the socket is torn down and wait for all callbacks
    {
        const auto lock = m_lock.lock();
        m_adapterStatus = AdapterStatus::Disabled;
        m_socket.reset();
    }
    m_threadpoolIo.reset();
}

StreamClient::StreamClient(ctl::ctSockaddr targetAddress, unsigned long receiveBufferCount, HANDLE completeEvent) :
    m_targetAddress(std::move(targetAddress)), m_completeEvent(completeEvent), m_receiveBufferCount(receiveBufferCount)
{
    m_threadpoolTimer = std::make_unique<ThreadpoolTimer>([this]() noexcept { TimerCallback(); });

    // initialize the send buffer
    for (size_t i = 0; i < m_sharedSendBuffer.size(); ++i)
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

        Log<LogLevel::Output>("Secondary wlan interfaces enabled\n");
    }
}

void StreamClient::SetupSecondaryInterface()
{
    if (!m_wlanHandle)
    {
        Log<LogLevel::Debug>("StreamClient::SetupSecondaryInterface - Secondary wlan connection not requested\n");
        return;
    }

    // Callback to update the secondary interface state in response to network status events
    auto updateSecondaryInterfaceStatus = [this, primaryInterfaceGuid = winrt::guid{}, secondaryInterfaceGuid = winrt::guid{}]() mutable {
        Log<LogLevel::Debug>("StreamClient::SetupSecondaryInterface - Network changed event received\n");
        // Check if the primary interface changed
        auto connectedInterfaceGuid = GetPrimaryInterfaceGuid();

        // If the default internet ip interface changes, the secondary wlan interface status changes too
        if (connectedInterfaceGuid != primaryInterfaceGuid)
        {
            Log<LogLevel::Debug>("StreamClient::SetupSecondaryInterface - The preferred primary interface changed\n");
            primaryInterfaceGuid = connectedInterfaceGuid;

            // If a secondary wlan interface was used for the previous primary, tear it down
            if (m_secondaryState.m_adapterStatus == AdapterStatus::Ready)
            {
                m_secondaryState.Cancel();
                Log<LogLevel::Info>("Secondary interface removed\n");
            }

            // If a secondary wlan interface is available for the new primary interface, get ready to use it
            if (auto secondaryGuid = GetSecondaryInterfaceGuid(m_wlanHandle.get(), primaryInterfaceGuid))
            {
                secondaryInterfaceGuid = *secondaryGuid;
                m_secondaryState.m_adapterStatus = AdapterStatus::Connecting;
                Log<LogLevel::Info>("Secondary interface added. Waiting for connectivity.\n");
            }
        }

        // Once the secondary interface has network connectivity, setup it up for sending data
        if (m_secondaryState.m_adapterStatus == AdapterStatus::Connecting && IsAdapterConnected(secondaryInterfaceGuid))
        {
            auto lock = m_secondaryState.m_lock.lock();
            Log<LogLevel::Debug>(
                "StreamClient::SetupSecondaryInterface - Secondary interface connected. Setting up a socket.\n");
            m_secondaryState.Setup(m_targetAddress, m_receiveBufferCount, ConvertInterfaceGuidToIndex(secondaryInterfaceGuid));

            for (auto& receiveState : m_secondaryState.m_receiveStates)
            {
                InitiateReceive(m_secondaryState, receiveState);
            }

            // The secondary interface is ready to send data, the client can start using it
            m_secondaryState.m_adapterStatus = AdapterStatus::Ready;
            Log<LogLevel::Info>("Secondary interface ready for use.\n");
        }
    };

    // Initial setup
    updateSecondaryInterfaceStatus();

    // Subscribe for network status updates
    m_networkInformationEventRevoker = NetworkInformation::NetworkStatusChanged(
        winrt::auto_revoke, [updateSecondaryInterfaceStatus = std::move(updateSecondaryInterfaceStatus)](const auto&) mutable {
            updateSecondaryInterfaceStatus();
        });
}

void StreamClient::Start(unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration)
{
    // Ensure we are stopped
    if (m_running)
    {
        Stop();
    }

    m_frameRate = sendFrameRate;
    const auto tickInterval = CalculateTickInterval(sendBitRate, sendFrameRate, c_sendBufferSize);
    m_tickInterval = ConvertHundredNanosToRelativeFiletime(tickInterval);
    const auto nbDatagramToSend = CalculateNumberOfDatagramToSend(duration, sendBitRate, c_sendBufferSize);
    m_finalSequenceNumber += nbDatagramToSend;

    Log<LogLevel::Output>(
        "Sending %d datagrams, by groups of %d every %lld hundred nanoseconds\n", nbDatagramToSend, m_frameRate, tickInterval);

    // allocate statistics buffer
    FAIL_FAST_IF_MSG(m_finalSequenceNumber > MAXSIZE_T, "Final sequence number exceeds limit of vector storage");
    m_latencyData.resize(static_cast<size_t>(m_finalSequenceNumber));

    // Setup the interfaces
    m_primaryState.Setup(m_targetAddress, m_receiveBufferCount);
    m_primaryState.m_adapterStatus = AdapterStatus::Ready;

    SetupSecondaryInterface();

    // initiate receives before starting the send timer
    for (auto& receiveState : m_primaryState.m_receiveStates)
    {
        InitiateReceive(m_primaryState, receiveState);
    }

    // start sending data
    m_running = true;
    Log<LogLevel::Debug>("StreamClient::Start - scheduling timer callback\n");
    m_threadpoolTimer->Schedule(m_tickInterval);
}

void StreamClient::Stop()
{
    Log<LogLevel::Debug>("StreamClient::Stop - stop sending datagrams\n");
    // Stop sending datagrams.
    // One more send operation could execute after this point if the callback is running concurrently to this call
    // Do not wait on the callback: we could be called by it
    m_running = false;
    m_threadpoolTimer->Stop();

    Log<LogLevel::Debug>("StreamClient::Stop - canceling network information event subscription\n");
    m_networkInformationEventRevoker.revoke();

    // Wait a little for in-flight packets (we don't want to count them as lost)
    Sleep(1000); // 1 sec

    Log<LogLevel::Debug>("StreamClient::Stop - closing sockets\n");
    m_primaryState.Cancel();
    m_secondaryState.Cancel();

    Log<LogLevel::Debug>("StreamClient::Stop - the client has stopped\n");
    SetEvent(m_completeEvent);
}

void StreamClient::PrintStatistics()
{
    PrintLatencyStatistics(m_latencyData);

    std::cout << '\n';
    std::cout << "Corrupt frames on primary interface: " << m_primaryState.m_corruptFrames << '\n';
    std::cout << "Corrupt frames on secondary interface: " << m_secondaryState.m_corruptFrames << '\n';
}

void StreamClient::DumpLatencyData(std::ofstream& file)
{
    multipath::DumpLatencyData(m_latencyData, file);
}

void StreamClient::TimerCallback() noexcept
{
    if (!m_running)
    {
        return;
    }

    for (auto i = 0; i < m_frameRate && m_sequenceNumber < m_finalSequenceNumber; ++i)
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
        Log<LogLevel::Debug>("StreamClient::TimerCallback - final sequence number sent, canceling timer callback\n");
        FAIL_FAST_IF_MSG(m_sequenceNumber > m_finalSequenceNumber, "FATAL: Exceeded the expected number of packets sent");
        Stop();
    }
}

void StreamClient::SendDatagrams() noexcept
{
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
        Log<LogLevel::Error>("StreamClient::SendDatagram - invalid socket, ignoring send request\n");
        return;
    }

    DatagramSendRequest sendRequest{m_sequenceNumber, m_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();
    const SendState sendState{m_sequenceNumber, sendRequest.GetQpc()};

    Log<LogLevel::All>(
        "StreamClient::SendDatagram - sending sequence number %lld on %s socket %zu\n",
        m_sequenceNumber,
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get());

    auto callback = [this, &socketState, sendState](OVERLAPPED* ov) noexcept {
        try
        {
            auto lock = socketState.m_lock.lock();

            if (!socketState.m_socket.is_valid())
            {
                Log<LogLevel::Debug>("StreamClient::SendDatagram - The socket is no longer valid, ignoring send completion\n");
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
                const auto lastError = WSAGetLastError();
                Log<LogLevel::Error>("StreamClient::SendDatagram - WSASend failed : %u\n", lastError);
            }
        }
        catch (...)
        {
            FAIL_FAST_CAUGHT_EXCEPTION_MSG("FATAL: Unhandled exception in send completion callback");
        }
    };

    OVERLAPPED* ov = socketState.m_threadpoolIo->new_request(callback);

    auto error = WSASend(socketState.m_socket.get(), buffers.data(), static_cast<DWORD>(buffers.size()), nullptr, 0, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            socketState.m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "WSASend failed");
        }
    }
}

void StreamClient::SendCompletion(SocketState& socketState, const SendState& sendState) noexcept
{
    FAIL_FAST_IF_MSG(sendState.m_sequenceNumber > MAXSIZE_T, "FATAL: sequence number out of bounds of vector");
    auto& stat = m_latencyData[static_cast<unsigned int>(sendState.m_sequenceNumber)];

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

    if (!socketState.m_socket.is_valid())
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

        if (!socketState.m_socket.is_valid())
        {
            Log<LogLevel::Debug>("StreamClient::InitiateReceive [callback] - The socket is no longer valid, ignoring receive completion\n");
            return;
        }

        DWORD bytesTransferred = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(socketState.m_socket.get(), ov, &bytesTransferred, false, &flags))
        {
            const auto lastError = WSAGetLastError();
            FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSARecv failed : %u", lastError);
        }

        ReceiveCompletion(socketState, receiveState, bytesTransferred);
        InitiateReceive(socketState, receiveState);
    };

    DWORD bytesTransferred = 0;
    OVERLAPPED* ov = socketState.m_threadpoolIo->new_request(callback);

    Log<LogLevel::All>("StreamClient::InitiateReceive - initiating WSARecv on socket %zu\n", socketState.m_socket.get());

    auto error = WSARecv(socketState.m_socket.get(), &wsabuf, 1, &bytesTransferred, &flags, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            socketState.m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "WSARecv failed");
        }
    }
}

void StreamClient::ReceiveCompletion(SocketState& socketState, ReceiveState& receiveState, DWORD messageSize) noexcept
try
{
    FAIL_FAST_IF_MSG(!ValidateBufferLength(receiveState.m_buffer.data(), receiveState.m_buffer.size(), messageSize), "Received invalid message");

    const auto& header = ParseDatagramHeader(receiveState.m_buffer.data());

    Log<LogLevel::All>(
        "StreamClient::ReceiveCompletion - received sequence number %lld on %s socket %zu\n",
        header.m_sequenceNumber,
        socketState.m_interface == Interface::Primary ? "primary" : "secondary",
        socketState.m_socket.get());

    if (header.m_sequenceNumber < 0 || header.m_sequenceNumber >= m_finalSequenceNumber)
    {
        Log<LogLevel::Debug>("StreamClient::ReceiveCompletion - received corrupt frame, sequence number: %lld\n", header.m_sequenceNumber);
        socketState.m_corruptFrames += 1;
        return;
    }

    auto& stat = m_latencyData[static_cast<size_t>(header.m_sequenceNumber)];
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