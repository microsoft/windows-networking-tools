#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <wil/result.h>

//
namespace multipath {
inline SOCKET CreateDatagramSocket(short family = AF_INET)
{
    const DWORD flags = WSA_FLAG_OVERLAPPED;
    SOCKET socket = WSASocket(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, flags);

    if (INVALID_SOCKET == socket)
    {
        THROW_WIN32_MSG(WSAGetLastError(), "WSASocket failed");
    }

    return socket;
}

inline void SetSocketOutgoingInterface(SOCKET socket, short family, int outgoingIfIndex)
{
    if (outgoingIfIndex == 0)
    {
        // do nothing if no interface index given
        return;
    }

    if (family == AF_INET)
    {
        // interface index should be in network byte order for IPPROTO_IP
        const DWORD value = htonl(outgoingIfIndex);
        auto length = static_cast<int>(sizeof(value));
        const auto error = setsockopt(socket, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char*>(&value), length);
        if (ERROR_SUCCESS != error)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "setsockopt(IPPROTO_IP, IP_UNICAST_IF) failed");
        }
    }
    else if (family == AF_INET6)
    {
        // interface index should be in host byte order for IPPROTO_IPV6
        auto length = static_cast<int>(sizeof(outgoingIfIndex));
        const auto error = setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<const char*>(&outgoingIfIndex), length);
        if (ERROR_SUCCESS != error)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "setsockopt(IPPROTO_IPV6, IPV6_UNICAST_IF) failed");
        }
    }
    else
    {
        FAIL_FAST_MSG("unexpected address family");
    }
}

inline void SetSocketReceiveBufferSize(SOCKET socket, DWORD size)
{
    const auto value = size;
    const auto length = static_cast<int>(sizeof(value));
    const auto error = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&value), length);
    if (ERROR_SUCCESS != error)
    {
        THROW_WIN32_MSG(WSAGetLastError(), "setsocktopt(SOL_SOCKET, SO_RCVBUF) failed");
    }
}

} // namespace multipath