#pragma once

#include <Windows.h>

#include <wil/resource.h>

#include <array>
#include <functional>
#include <memory>

#include "latencyStatistics.h"
#include "sockaddr.h"
#include "threadpool_io.h"

namespace multipath {

class MeasuredSocket
{
public:
    // Size of the buffer used to send or receive
    static constexpr size_t c_bufferSize = 1024; // 1KB

    enum class AdapterStatus
    {
        Disabled,
        Connecting,
        Ready
    };

    struct SendResult
    {
        long long m_sequenceNumber;
        long long m_sendTimestamp; // Microsec
    };

    struct ReceiveResult
    {
        long long m_sequenceNumber;
        long long m_sendTimestamp; // Microsec
        long long m_receiveTimestamp; // Microsec
        long long m_echoTimestamp; // Microsec
    };

    MeasuredSocket() = default;

    // Not copyable or movable
    MeasuredSocket(const MeasuredSocket&) = delete;
    MeasuredSocket& operator=(const MeasuredSocket&) = delete;
    MeasuredSocket(MeasuredSocket&&) = delete;
    MeasuredSocket& operator=(MeasuredSocket&&) = delete;
    ~MeasuredSocket() noexcept;

    void Setup(const ctl::ctSockaddr& targetAddress, int numReceivedBuffers, int interfaceIndex = 0);
    void Cancel() noexcept;

    void CheckConnectivity();
    void PrepareToReceive(std::function<void(ReceiveResult&)> clientCallback) noexcept;

    void SendDatagram(long long sequenceNumber, std::function<void(const SendResult&)> clientCallback) noexcept;

    std::atomic<AdapterStatus> m_adapterStatus{AdapterStatus::Disabled};
    long long m_corruptFrames = 0;

private:
    struct ReceiveState
    {
        std::array<char, c_bufferSize> m_buffer{};
        long long m_receiveTimestamp{};
    };

    void PrepareToReceiveDatagram(ReceiveState& receiveState, std::function<void(ReceiveResult&)> clientCallback) noexcept;
    void PrepareToReceivePing(wil::shared_event pingReceived);
    void PingEchoServer();

    // the contexts used for each posted receive
    std::vector<ReceiveState> m_receiveStates;

    wil::critical_section m_lock{500};
    wil::unique_socket m_socket;
    std::unique_ptr<ctl::ctThreadIocp> m_threadpoolIo;

    // All interfaces are sending the same data, stored in a shared buffer
    static constexpr const std::array<char, c_bufferSize> s_sharedSendBuffer = []() {
        // initialize the send buffer
        std::array<char, c_bufferSize> sharedSendBuffer{};
        for (size_t i = 0; i < sharedSendBuffer.size(); ++i)
        {
            sharedSendBuffer[i] = static_cast<char>(i);
        }
        return sharedSendBuffer;
    }();
};

} // namespace multipath
