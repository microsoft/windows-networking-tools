#pragma once

#include "sockaddr.h"
#include "threadpool_io.h"

#include <WinSock2.h>
#include <wil/resource.h>

#include <array>

namespace multipath {
class StreamServer
{
public:
    StreamServer(ctl::ctSockaddr listenAddress);

    ~StreamServer() noexcept = default;

    void Start(unsigned long receiveBufferCount);

    // not copyable or movable
    StreamServer(const StreamServer&) = delete;
    StreamServer& operator=(const StreamServer&) = delete;
    StreamServer(StreamServer&&) = delete;
    StreamServer& operator=(StreamServer&&) = delete;

private:
    static constexpr std::size_t c_receiveBufferSize = 1024; // 1KB receive buffer
    using ReceiveBuffer = std::array<char, c_receiveBufferSize>;

    struct ReceiveContext
    {
        ReceiveBuffer m_buffer{};
        ctl::ctSockaddr m_remoteAddress{};
        int m_remoteAddressLen = 0;
        DWORD m_receiveFlags = 0;
    };

    void InitiateReceive(ReceiveContext& receiveContext);

    void CompleteReceive(ReceiveContext& receiveContext, OVERLAPPED* ov) noexcept;

    ctl::ctSockaddr m_listenAddress;

    wil::unique_socket m_socket;
    std::unique_ptr<ctl::ctThreadIocp> m_threadpoolIo;

    std::vector<ReceiveContext> m_receiveContexts;
};
} // namespace multipath