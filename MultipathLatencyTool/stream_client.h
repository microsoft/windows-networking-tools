#pragma once

#include <Windows.h>
#include <wil/resource.h>

#include <array>
#include <memory>
#include <vector>

#include "sockaddr.h"
#include "threadpool_io.h"
#include "threadpool_timer.h"

namespace multipath {

class StreamClient
{
public:
    StreamClient(ctl::ctSockaddr targetAddress, int primaryInterfaceIndex, int secondaryInterfaceIndex, HANDLE completeEvent);

    void Start(unsigned long receiveBufferCount, unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration);
    void Stop();

    void PrintStatistics();

    // not copyable or movable
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

    static constexpr size_t c_sendBufferSize = 1024; // 1KB send buffer
    using SendBuffer = std::array<char, c_sendBufferSize>;

    struct SendState
    {
        long long m_sequenceNumber;
        long long m_qpc;
    };

    static constexpr size_t c_receiveBufferSize = 1024; // 1KB receive buffer
    using ReceiveBuffer = std::array<char, c_receiveBufferSize>;

    struct ReceiveState
    {
        ctl::ctSockaddr m_remoteAddress{};
        int m_remoteAddressLen{};
        ReceiveBuffer m_buffer{};
        long long m_qpc{};
    };

    struct SocketState
    {
        ~SocketState() noexcept
        {
            // guarantee the socket is torn down and TP stopped
            // before freeing member buffers
            {
                const auto lock = m_lock.lock();
                m_socket.reset();
            }
            m_threadpoolIo.reset();
        }
        wil::critical_section m_lock{500};
        wil::unique_socket m_socket;
        std::unique_ptr<ctl::ctThreadIocp> m_threadpoolIo;

        wil::unique_event m_connectEvent{wil::EventOptions::ManualReset};

        // the interface index the socket will send outgoing data
        int m_interfaceIndex;

        // whether the this socket is the primary or secondary
        Interface m_interface;

        // the contexts used for each posted receive
        std::vector<ReceiveState> m_receiveStates;

        long long m_sentFrames = 0;
        long long m_receivedFrames = 0;
        long long m_corruptFrames = 0;
    };

    void Connect(SocketState& socketState);

    void TimerCallback() noexcept;

    void SendDatagrams() noexcept;
    void SendDatagram(SocketState& socketState) noexcept;
    void SendCompletion(SocketState& socketState, const SendState& sendState) noexcept;

    void InitiateReceive(SocketState& socketState, ReceiveState& receiveState);
    void ReceiveCompletion(SocketState& socketState, ReceiveState& receiveState, DWORD messageSize) noexcept;

    ctl::ctSockaddr m_targetAddress{};

    // indicates which interface the datagram should be sent on first
    // this alternates between Primary and Secondary to reduce the chance
    // of the order in which datagrams are sent affecting the total latency
    Interface m_whichFirst = Interface::Primary;
    SocketState m_primaryState{};
    SocketState m_secondaryState{};

    // The number of datagrams to send on each timer callback
    long long m_frameRate = 0;

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

        long long m_primarySendQpc = -1;
        long long m_secondarySendQpc = -1;

        long long m_primaryLatencyMs = -1;
        long long m_secondaryLatencyMs = -1;
    };

    std::vector<LatencyStatistic> m_latencyStatistics;

    HANDLE m_completeEvent = nullptr;
};
} // namespace multipath