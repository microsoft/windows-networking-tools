#pragma once

#include <Windows.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <wlanapi.h>

#include <wil/resource.h>

#include <array>
#include <memory>
#include <optional>
#include <vector>

#include "sockaddr.h"
#include "threadpool_io.h"
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
    void Stop();

    void PrintStatistics();
    void DumpLatencyData(std::ofstream& file);

    // not copyable or movable
    StreamClient(const StreamClient&) = delete;
    StreamClient& operator=(const StreamClient&) = delete;
    StreamClient(StreamClient&&) = delete;
    StreamClient& operator=(StreamClient&&) = delete;

    ~StreamClient() = default;

private:
    NetworkInformation::NetworkStatusChanged_revoker m_networkInformationEventRevoker{};
    // The client must keep this handle open to keep the secondary STA port active
    wil::unique_wlan_handle m_wlanHandle;

    enum class Interface
    {
        Primary,
        Secondary
    };

    static constexpr size_t c_sendBufferSize = 1024; // 1KB send buffer
    using SendBuffer = std::array<char, c_sendBufferSize>;

    struct SendState
    {
        long long m_sequenceNumber;
        long long m_sendTimestamp;
    };

    static constexpr size_t c_receiveBufferSize = 1024; // 1KB receive buffer
    struct ReceiveState
    {
        std::array<char, c_receiveBufferSize> m_buffer{};
        long long m_receiveTimestamp{};
    };

            
    enum class AdapterStatus
    {
        Disabled,
        Connecting,
        Ready
    };

    struct SocketState
    {
        ~SocketState() noexcept
        {
            // guarantee the socket is torn down and TP stopped before freeing member buffers
            {
                const auto lock = m_lock.lock();
                m_socket.reset();
            }
            m_threadpoolIo.reset();
        }
        wil::critical_section m_lock{500};
        wil::unique_socket m_socket;
        std::unique_ptr<ctl::ctThreadIocp> m_threadpoolIo;

        // the interface index the socket will send outgoing data
        int m_interfaceIndex;

        // whether the this socket is the primary or secondary
        Interface m_interface;

        // the contexts used for each posted receive
        std::vector<ReceiveState> m_receiveStates;

        long long m_sentFrames = 0;
        long long m_receivedFrames = 0;
        long long m_corruptFrames = 0;

        AdapterStatus m_adapterStatus{AdapterStatus::Disabled};
    };

    void Connect(SocketState& socketState);
    void SetupSecondaryInterface();

    void TimerCallback() noexcept;

    void SendDatagrams() noexcept;
    void SendDatagram(SocketState& socketState) noexcept;
    void SendCompletion(SocketState& socketState, const SendState& sendState) noexcept;

    void InitiateReceive(SocketState& socketState, ReceiveState& receiveState);
    void ReceiveCompletion(SocketState& socketState, ReceiveState& receiveState, DWORD messageSize) noexcept;

    ctl::ctSockaddr m_targetAddress{};

    SocketState m_primaryState{};
    SocketState m_secondaryState{};

    // TODO: Move somewhere better...
    winrt::guid m_primaryInterfaceGuid;
    winrt::guid m_secondaryInterfaceGuid;

    // The number of datagrams to send on each timer callback
    long long m_frameRate = 0;
    unsigned long m_receiveBufferCount = 1;

    FILETIME m_tickInterval{};
    long long m_finalSequenceNumber = 0;
    std::unique_ptr<ThreadpoolTimer> m_threadpoolTimer{};
    bool m_stopCalled = false;

    // both the primary and secondary socket will use the same send buffer so that the message payloads are identical
    long long m_sequenceNumber = 0;
    SendBuffer m_sharedSendBuffer{};

    struct LatencyStatistic
    {
        long long m_sequenceNumber = -1;

        long long m_primarySendTimestamp = -1;
        long long m_secondarySendTimestamp = -1;

        long long m_primaryEchoTimestamp = -1;
        long long m_secondaryEchoTimestamp = -1;

        long long m_primaryReceiveTimestamp = -1;
        long long m_secondaryReceiveTimestamp = -1;
    };

    std::vector<LatencyStatistic> m_latencyStatistics;

    HANDLE m_completeEvent = nullptr;
};
} // namespace multipath