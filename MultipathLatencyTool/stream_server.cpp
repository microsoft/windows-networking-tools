#include "pch.h"

#include "stream_server.h"
#include "socket_utils.h"
#include "debug.h"
#include "datagram.h"

namespace multipath {
StreamServer::StreamServer(const Sockaddr& listenAddress) : m_listenAddress(listenAddress)
{
    constexpr int DefaultSocketReceiveBufferSize = 1048576; // 1MB socket receive buffer

    m_socket.reset(CreateDatagramSocket());
    SetSocketReceiveBufferSize(m_socket.get(), DefaultSocketReceiveBufferSize); // TODO: add config parameter

    auto error = bind(m_socket.get(), m_listenAddress.sockaddr(), m_listenAddress.length());
    if (SOCKET_ERROR == error)
    {
        THROW_WIN32_MSG(WSAGetLastError(), "bind failed");
    }

    m_threadpoolIo = std::make_unique<ThreadpoolIo>(m_socket.get());
}

void StreamServer::Start(unsigned long prePostRecvs)
{
    // allocate our receive contexts
    m_receiveContexts.resize(prePostRecvs);

    // post a receive for each buffer
    for (auto& receiveContext : m_receiveContexts)
    {
        InitiateReceive(receiveContext);
    }
}

void StreamServer::InitiateReceive(ReceiveContext& receiveContext)
{
    receiveContext.remoteAddressLen = receiveContext.remoteAddress.length();

    WSABUF wsabuf;
    wsabuf.buf = receiveContext.buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveContext.buffer.size());

    OVERLAPPED* ov =
        m_threadpoolIo->NewRequest([this, &receiveContext](OVERLAPPED* ov) noexcept { ReceiveCompletion(receiveContext, ov); });

    auto error = WSARecvFrom(
        m_socket.get(),
        &wsabuf,
        1,
        nullptr,
        &receiveContext.receiveFlags,
        receiveContext.remoteAddress.sockaddr(),
        &receiveContext.remoteAddressLen,
        ov,
        nullptr);

    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            // must cancel the threadpool IO request
            m_threadpoolIo->CancelRequest(ov);
            FAIL_FAST_WIN32_MSG(error, "WSARecvFrom failed");
        }
    }
}

void StreamServer::ReceiveCompletion(ReceiveContext& receiveContext, OVERLAPPED* ov) noexcept
{
    DWORD bytesReceived = 0;
    if (WSAGetOverlappedResult(m_socket.get(), ov, &bytesReceived, FALSE, &receiveContext.receiveFlags))
    {
        auto header = ExtractDatagramHeaderFromBuffer(receiveContext.buffer.data(), receiveContext.buffer.size());

        PRINT_DEBUG_INFO("\tStreamServer::ReceiveCompletion - echoing sequence number %lld\n", header.sequenceNumber);

        // echo the data received
        WSABUF wsabuf;
        wsabuf.buf = receiveContext.buffer.data();
        wsabuf.len = bytesReceived;

        OVERLAPPED* echoOv = m_threadpoolIo->NewRequest([](OVERLAPPED*) noexcept {});

        auto error = WSASendTo(
            m_socket.get(), &wsabuf, 1, nullptr, 0, receiveContext.remoteAddress.sockaddr(), receiveContext.remoteAddressLen, echoOv, nullptr);
        if (SOCKET_ERROR == error)
        {
            error = WSAGetLastError();
            if (WSA_IO_PENDING != error)
            {
                // best effort send
                m_threadpoolIo->CancelRequest(echoOv);
                FAILED_WIN32_LOG(error);
            }
        }
    }

    // post another receive
    InitiateReceive(receiveContext);
}
} // namespace multipath