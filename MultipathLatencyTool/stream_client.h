#pragma once

#include <Windows.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <wlanapi.h>

#include <wil/resource.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <vector>

#include "latencyStatistics.h"
#include "measuredSocket.h"
#include "threadpool_timer.h"

using namespace winrt;
using namespace Windows::Networking::Connectivity;

namespace multipath {

class StreamClient
{
public:
    StreamClient(ctl::ctSockaddr targetAddress, unsigned long receiveBufferCount, HANDLE completeEvent);

    void RequestSecondaryWlanConnection();

    void Start(unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration);
    void Stop() noexcept;

    void PrintStatistics();
    void DumpLatencyData(std::ofstream& file);

    // Not copyable or movable
    StreamClient(const StreamClient&) = delete;
    StreamClient& operator=(const StreamClient&) = delete;
    StreamClient(StreamClient&&) = delete;
    StreamClient& operator=(StreamClient&&) = delete;

    ~StreamClient() = default;

private:
    enum class Interface
    {
        Primary,
        Secondary
    };

    NetworkInformation::NetworkStatusChanged_revoker m_networkInformationEventRevoker{};
    // The client must keep this handle open to keep the secondary STA port active
    wil::unique_wlan_handle m_wlanHandle;

    void SetupSecondaryInterface();

    void TimerCallback() noexcept;

    void SendDatagrams() noexcept;
    void SendCompletion(const Interface interface, const MeasuredSocket::SendResult& sendState) noexcept;
    void ReceiveCompletion(const Interface interface, const MeasuredSocket::ReceiveResult& result) noexcept;

    ctl::ctSockaddr m_targetAddress{};

    MeasuredSocket m_primaryState{};
    MeasuredSocket m_secondaryState{};

    // The number of datagrams to send on each timer callback
    long long m_frameRate = 0;
    unsigned long m_receiveBufferCount = 1;

    std::unique_ptr<ThreadpoolTimer> m_threadpoolTimer{};
    std::atomic<bool> m_running = false;

    // Initialize to -1 as the first datagram has sequence number 0
    long long m_finalSequenceNumber = -1;
    long long m_sequenceNumber = 0;

    LatencyData m_latencyData;

    HANDLE m_completeEvent = nullptr;
};
} // namespace multipath