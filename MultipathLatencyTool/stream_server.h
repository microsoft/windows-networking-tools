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
    StreamServer(const Sockaddr& listenAddress);

    ~StreamServer() noexcept = default;

    void Start(unsigned long prePostRecvs);

    // not copyable or movable
    StreamServer(const StreamServer&) = delete;
    StreamServer& operator=(const StreamServer&) = delete;
    StreamServer(StreamServer&&) = delete;
    StreamServer& operator=(StreamServer&&) = delete;

private:
    static constexpr std::size_t ReceiveBufferSize = 1024; // 1KB receive buffer
    using ReceiveBuffer = std::array<char, ReceiveBufferSize>;

    struct ReceiveContext
    {
        ReceiveBuffer buffer;
        Sockaddr remoteAddress;
        int remoteAddressLen;
        DWORD receiveFlags;
    };

    void InitiateReceive(ReceiveContext& receiveContext);

    void ReceiveCompletion(ReceiveContext& receiveContext, OVERLAPPED* ov) noexcept;

    Sockaddr m_listenAddress;

    wil::unique_socket m_socket;
    std::unique_ptr<ThreadpoolIo> m_threadpoolIo;

    std::vector<ReceiveContext> m_receiveContexts;
};
} // namespace multipath