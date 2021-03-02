#include "stream_server.h"
#include "socket_utils.h"
#include "debug.h"
#include "datagram.h"

namespace multipath {
StreamServer::StreamServer(ctl::ctSockaddr listenAddress) :
    m_listenAddress{std::move(listenAddress)}, m_socket{CreateDatagramSocket()}
{
    constexpr int defaultSocketReceiveBufferSize = 1048576; // 1MB socket receive buffer
    SetSocketReceiveBufferSize(m_socket.get(), defaultSocketReceiveBufferSize); // TODO: add config parameter

    const auto error = bind(m_socket.get(), m_listenAddress.sockaddr(), m_listenAddress.length());
    if (SOCKET_ERROR == error)
    {
        THROW_WIN32_MSG(WSAGetLastError(), "bind failed");
    }

    m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_socket.get());
}

void StreamServer::Start(unsigned long receiveBufferCount)
{
    // allocate our receive contexts
    m_receiveContexts.resize(receiveBufferCount);

    // post a receive for each buffer
    for (auto& receiveContext : m_receiveContexts)
    {
        InitiateReceive(receiveContext);
    }
}

void StreamServer::InitiateReceive(ReceiveContext& receiveContext)
{
    receiveContext.m_remoteAddressLen = receiveContext.m_remoteAddress.length();

    WSABUF wsabuf;
    wsabuf.buf = receiveContext.m_buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveContext.m_buffer.size());

    OVERLAPPED* ov =
        m_threadpoolIo->new_request([this, &receiveContext](OVERLAPPED* ov) noexcept { CompleteReceive(receiveContext, ov); });

    const auto error = WSARecvFrom(
        m_socket.get(),
        &wsabuf,
        1,
        nullptr,
        &receiveContext.m_receiveFlags,
        receiveContext.m_remoteAddress.sockaddr(),
        &receiveContext.m_remoteAddressLen,
        ov,
        nullptr);

    if (SOCKET_ERROR == error)
    {
        const auto lastError = WSAGetLastError();
        if (WSA_IO_PENDING != lastError)
        {
            // must cancel the threadpool IO request
            m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(lastError, "WSARecvFrom failed");
        }
    }
}

void StreamServer::CompleteReceive(ReceiveContext& receiveContext, OVERLAPPED* ov) noexcept
{
    DWORD bytesReceived = 0;
    if (WSAGetOverlappedResult(m_socket.get(), ov, &bytesReceived, false, &receiveContext.m_receiveFlags))
    {
        const auto header = ExtractDatagramHeaderFromBuffer(receiveContext.m_buffer.data(), receiveContext.m_buffer.size());

        PRINT_DEBUG_INFO("\tStreamServer::ReceiveCompletion - echoing sequence number %lld\n", header.m_sequenceNumber);

        // echo the data received. A synchronous send is enough.
        WSABUF wsabuf;
        wsabuf.buf = receiveContext.m_buffer.data();
        wsabuf.len = bytesReceived;

        const auto error = WSASendTo(
            m_socket.get(), &wsabuf, 1, nullptr, 0, receiveContext.m_remoteAddress.sockaddr(), receiveContext.m_remoteAddressLen, nullptr, nullptr);
        if (SOCKET_ERROR == error)
        {
            // best effort send
            FAILED_WIN32_LOG(WSAGetLastError());
        }
    }
    else
    {
        const auto lastError = WSAGetLastError();
        PRINT_DEBUG_INFO("\tStreamServer::ReceiveCompletion - WSARecvFrom failed %u\n", lastError);
    }

    // post another receive
    InitiateReceive(receiveContext);
}
} // namespace multipath