#pragma once

#include <Windows.h>
#include <WinSock2.h>
#include <wil/resource.h>

#include <array>
#include <memory>

#include "sockaddr.h"
#include "threadpool_io.h"
#include "threadpool_timer.h"

namespace multipath {

class StreamClient
{
public:
    StreamClient(const Sockaddr& targetAddress, int primaryInterfaceIndex, int secondaryInterfaceIndex, HANDLE completeEvent);

    void Start(unsigned long prePostRecvs, unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration);
    void Stop();

    void PrintStatistics();

    // not copyable or movable
    StreamClient(const StreamClient&) = delete;
    StreamClient& operator=(const StreamClient&) = delete;
    StreamClient(StreamClient&&) = delete;
    StreamClient& operator=(StreamClient&&) = delete;

    ~StreamClient() noexcept;

private:
    enum class Interface
    {
        Primary,
        Secondary
    };

    static constexpr size_t SendBufferSize = 1024; // 1KB send buffer
    using SendBuffer = std::array<char, SendBufferSize>;

    struct SendState
    {
        long long sequenceNumber;
        long long qpc;
    };

    static constexpr size_t ReceiveBufferSize = 1024; // 1KB receive buffer
    using ReceiveBuffer = std::array<char, ReceiveBufferSize>;

    struct ReceiveState
    {
        Sockaddr remoteAddress;
        int remoteAddressLen;
        ReceiveBuffer buffer;
        long long qpc;
    };

    struct SocketState
    {
        wil::critical_section csSocket;
        wil::unique_socket socket;
        std::unique_ptr<ThreadpoolIo> threadpoolIo;

        HANDLE connectEvent = INVALID_HANDLE_VALUE;

        // the interface index the socket will send outgoing data
        int interfaceIndex;

        // whether the this socket is the primary or secondary
        Interface interface;

        // the contexts used for each posted recieve
        std::vector<ReceiveState> receiveStates;

        long long sentFrames = 0;
        long long receivedFrames = 0;
        long long corruptFrames = 0;
    };

    void Connect(SocketState& socketState);

    // The number of datagrams to send on each timer callback
    long long m_frameRate;

    void TimerCallback() noexcept;

    void SendDatagrams() noexcept;
    void SendDatagram(SocketState& socketState) noexcept;
    void SendCompletion(SocketState& socketState, const SendState& sendState) noexcept;

    void InitiateReceive(SocketState& socketState, ReceiveState& receiveState);
    void ReceiveCompletion(SocketState& socketState, ReceiveState& receiveState, DWORD messageSize) noexcept;

    Sockaddr m_targetAddress;

    // indicates which interface the datagram should be sent on first
    // this alternates between Primary and Secondary to reduce the chance
    // of the order in which datagrams are sent affecting the total latency
    Interface m_whichFirst = Interface::Primary;
    SocketState m_primaryState;
    SocketState m_secondaryState;

    FILETIME m_tickInterval{};
    long long m_finalSequenceNumber = 0;
    std::unique_ptr<ThreadpoolTimer> m_threadpoolTimer;
    bool m_stopCalled = false;

    // both the primary and secondary socket will use the same send buffer so that the message payloads are identical
    long long m_sequenceNumber = 0;
    SendBuffer m_sharedSendBuffer{};

    struct LatencyStatistic
    {
        long long sequenceNumber = -1;

        long long primarySendQpc = -1;
        long long secondarySendQpc = -1;

        long long primaryLatencyMs = -1;
        long long secondaryLatencyMs = -1;
    };

    std::vector<LatencyStatistic> m_latencyStatistics;

    HANDLE m_completeEvent = nullptr;
};
} // namespace multipath