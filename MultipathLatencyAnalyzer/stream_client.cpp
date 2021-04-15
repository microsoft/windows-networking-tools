#include "stream_client.h"

#include "adapters.h"
#include "logs.h"

#include <wil/result.h>

#include <iostream>

namespace multipath {
namespace {

    // calculates the interval at which to set the timer callback to send data at the specified rate (in bits per second)
    constexpr long long CalculateTickInterval(long long bitRate, long long frameRate, unsigned long long datagramSize) noexcept
    {
        // bitRate -> bit/s, datagramSize -> byte, frameRate -> N/U
        // We look for the tick interval in 100 nanosecond
        const unsigned long hundredNanoSecInSecond = 10'000'000UL; // hundred ns / s
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

StreamClient::StreamClient(ctl::ctSockaddr targetAddress, unsigned long receiveBufferCount, HANDLE completeEvent) :
    m_targetAddress(std::move(targetAddress)), m_completeEvent(completeEvent), m_receiveBufferCount(receiveBufferCount)
{
    m_threadpoolTimer = std::make_unique<ThreadpoolTimer>([this]() noexcept { TimerCallback(); });
}

void StreamClient::RequestSecondaryWlanConnection()
{
    if (!m_wlanHandle)
    {
        // The handle to the wlan api must stay open to keep the secondary connection active
        m_wlanHandle = OpenWlanHandle();
        RequestSecondaryInterface(m_wlanHandle.get());

        Log<LogLevel::Dualsta>("Secondary wlan interfaces enabled\n");
    }
}

void StreamClient::SetupSecondaryInterface()
{
    if (!m_wlanHandle)
    {
        Log<LogLevel::Dualsta>("Secondary wlan connection not requested\n");
        return;
    }

    // Callback to update the secondary interface state in response to network status events
    auto updateSecondaryInterfaceStatus = [this, primaryInterfaceGuid = winrt::guid{}, secondaryInterfaceGuid = winrt::guid{}]() mutable {
        try
        {

            Log<LogLevel::Info>("Network status changed event received\n");

            // Check if the primary interface changed
            auto connectedInterfaceGuid = GetPrimaryInterfaceGuid();

            // If the default internet ip interface changes, the secondary wlan interface status changes too
            if (connectedInterfaceGuid != primaryInterfaceGuid)
            {
                primaryInterfaceGuid = connectedInterfaceGuid;
                Log<LogLevel::Dualsta>("The preferred primary interface changed. Updating the secondary interface.\n");

                // If a secondary wlan interface was used for the previous primary, tear it down
                if (m_secondaryState.m_adapterStatus == MeasuredSocket::AdapterStatus::Ready)
                {
                    m_secondaryState.Cancel();
                    Log<LogLevel::Dualsta>("Secondary interface removed\n");
                }

                // If a secondary wlan interface is available for the new primary interface, get ready to use it
                if (auto secondaryGuid = GetSecondaryInterfaceGuid(m_wlanHandle.get(), primaryInterfaceGuid))
                {
                    secondaryInterfaceGuid = *secondaryGuid;
                    m_secondaryState.m_adapterStatus = MeasuredSocket::AdapterStatus::Connecting;
                    Log<LogLevel::Dualsta>("Secondary interface added. Waiting for connectivity.\n");
                }
                else
                {
                    Log<LogLevel::Dualsta>("No secondary interface found for this primary.\n");
                }
            }

            // Once the secondary interface has network connectivity, setup it up for sending data
            if (m_secondaryState.m_adapterStatus == MeasuredSocket::AdapterStatus::Connecting && IsAdapterConnected(secondaryInterfaceGuid))
            {
                try
                {
                    Log<LogLevel::Dualsta>("Secondary interface connected. Setting up a socket.\n");
                    m_secondaryState.Setup(m_targetAddress, m_receiveBufferCount, ConvertInterfaceGuidToIndex(secondaryInterfaceGuid));
                    m_secondaryState.CheckConnectivity();
                    m_secondaryState.PrepareToReceive([this](auto& r) { ReceiveCompletion(Interface::Secondary, r); });

                    // The secondary interface is ready to send data, the client can start using it
                    m_secondaryState.m_adapterStatus = MeasuredSocket::AdapterStatus::Ready;
                    Log<LogLevel::Info>("Secondary interface ready for use.\n");
                }
                catch (wil::ResultException& ex)
                {
                    if (ex.GetErrorCode() == HRESULT_FROM_WIN32(ERROR_NOT_CONNECTED) ||
                        ex.GetErrorCode() == HRESULT_FROM_WIN32(WSAENETUNREACH))
                    {
                        Log<LogLevel::Dualsta>(
                            "Secondary interface could not reach the echo server. It will retry after a "
                            "network status change.");
                        m_secondaryState.Cancel();
                        m_secondaryState.m_adapterStatus = MeasuredSocket::AdapterStatus::Connecting;
                    }
                    else
                    {
                        FAIL_FAST_CAUGHT_EXCEPTION();
                    }
                }
            }
            else if (m_secondaryState.m_adapterStatus == MeasuredSocket::AdapterStatus::Ready && !IsAdapterConnected(secondaryInterfaceGuid))
            {
                m_secondaryState.Cancel();
                Log<LogLevel::Dualsta>("Secondary interface removed after losing connectivity\n");
            }
        }
        catch (...)
        {
            FAIL_FAST_CAUGHT_EXCEPTION();
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
    m_frameRate = sendFrameRate;
    const auto tickInterval = CalculateTickInterval(sendBitRate, sendFrameRate, MeasuredSocket::c_bufferSize);
    const auto nbDatagramToSend = CalculateNumberOfDatagramToSend(duration, sendBitRate, MeasuredSocket::c_bufferSize);
    m_finalSequenceNumber += nbDatagramToSend;

    // allocate statistics buffer
    FAIL_FAST_IF_MSG(m_finalSequenceNumber > MAXSIZE_T, "Final sequence number exceeds limit of vector storage");
    m_latencyData.m_latencies.resize(static_cast<size_t>(m_finalSequenceNumber));
    m_latencyData.m_datagramSize = MeasuredSocket::c_bufferSize;

    // Setup the interfaces
    Log<LogLevel::Info>("Setting up the interfaces\n");
    m_primaryState.Setup(m_targetAddress, m_receiveBufferCount);
    m_primaryState.CheckConnectivity();

    SetupSecondaryInterface();

    // initiate receives before starting the send timer
    m_primaryState.PrepareToReceive([this](auto& r) { ReceiveCompletion(Interface::Primary, r); });
    m_primaryState.m_adapterStatus = MeasuredSocket::AdapterStatus::Ready;

    Log<LogLevel::Output>(
        "%d datagrams will be sent, by groups of %d every %lld microseconds\n", nbDatagramToSend, m_frameRate, tickInterval / 10);

    // start sending data
    Log<LogLevel::Info>("Start sending datagrams\n");
    // TODO: Clean types
    m_threadpoolTimer->Schedule(static_cast<unsigned long>(tickInterval));
}

void StreamClient::Stop() noexcept
{
    Log<LogLevel::Info>("Stop sending datagrams\n");
    m_threadpoolTimer->Stop();

    Log<LogLevel::Info>("Canceling network status changed event subscription\n");
    m_networkInformationEventRevoker.revoke();

    // Wait a little for in-flight packets (we don't want to count them as lost)
    Sleep(1000); // 1 sec

    Log<LogLevel::Info>("Closing the sockets\n");
    m_primaryState.Cancel();
    m_secondaryState.Cancel();

    Log<LogLevel::Info>("The client has stopped\n");
    SetEvent(m_completeEvent);
}

void StreamClient::PrintStatistics()
{
    PrintLatencyStatistics(m_latencyData);
}

void StreamClient::DumpLatencyData(std::ofstream& file)
{
    multipath::DumpLatencyData(m_latencyData, file);
}

void StreamClient::TimerCallback() noexcept
{
    for (auto i = 0; i < m_frameRate && m_sequenceNumber < m_finalSequenceNumber; ++i)
    {
        SendDatagrams();
    }

    // Stop when the last sequence number is reached
    if (m_sequenceNumber >= m_finalSequenceNumber)
    {
        Log<LogLevel::Info>("Final sequence number sent, canceling timer callback\n");
        FAIL_FAST_IF_MSG(m_sequenceNumber > m_finalSequenceNumber, "Exceeded the expected number of packets sent");
        Stop();
    }
}

void StreamClient::SendDatagrams() noexcept
{
    m_primaryState.SendDatagram(m_sequenceNumber, [this](const auto& r) { SendCompletion(Interface::Primary, r); });

    if (m_secondaryState.m_adapterStatus == MeasuredSocket::AdapterStatus::Ready)
    {
        m_secondaryState.SendDatagram(
            m_sequenceNumber, [this](const auto& r) { SendCompletion(Interface::Secondary, r); });
    }

    m_sequenceNumber += 1;
}

void StreamClient::SendCompletion(const Interface interface, const MeasuredSocket::SendResult& sendState) noexcept
{
    auto& stat = m_latencyData.m_latencies[static_cast<size_t>(sendState.m_sequenceNumber)];

    if (interface == Interface::Primary)
    {
        stat.m_primarySendTimestamp = sendState.m_sendTimestamp;
    }
    else
    {
        stat.m_secondarySendTimestamp = sendState.m_sendTimestamp;
    }
}

void StreamClient::ReceiveCompletion(const Interface interface, const MeasuredSocket::ReceiveResult& result) noexcept
{
    if (result.m_sequenceNumber < 0 || result.m_sequenceNumber >= m_finalSequenceNumber)
    {
        Log<LogLevel::Debug>("Received a corrupt frame, sequence number: %lld\n", result.m_sequenceNumber);
        if (interface == Interface::Primary)
        {
            m_latencyData.m_primaryCorruptFrames += 1;
        }
        else
        {
            m_latencyData.m_secondaryCorruptFrames += 1;
        }
        return;
    }

    auto& stat = m_latencyData.m_latencies[static_cast<size_t>(result.m_sequenceNumber)];
    if (interface == Interface::Primary)
    {
        stat.m_primarySendTimestamp = result.m_sendTimestamp;
        stat.m_primaryEchoTimestamp = result.m_echoTimestamp;
        stat.m_primaryReceiveTimestamp = result.m_receiveTimestamp;
    }
    else
    {
        stat.m_secondarySendTimestamp = result.m_sendTimestamp;
        stat.m_secondaryEchoTimestamp = result.m_echoTimestamp;
        stat.m_secondaryReceiveTimestamp = result.m_receiveTimestamp;
    }
}

} // namespace multipath