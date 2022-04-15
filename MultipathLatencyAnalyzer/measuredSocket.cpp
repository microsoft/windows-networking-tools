// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "measuredSocket.h"

#include "adapters.h"
#include "datagram.h"
#include "logs.h"
#include "socket_utils.h"
#include "time_utils.h"

#include <Windows.h>
#include <winrt/Windows.Networking.Connectivity.h>

namespace multipath {

namespace {
    constexpr DWORD c_defaultSocketReceiveBufferSize = 1048576; // 1MB receive buffer
}

MeasuredSocket::~MeasuredSocket() noexcept
{
    // guarantee the socket is torn down and all callbacks are completed before freeing member buffers
    Cancel();
}

void MeasuredSocket::Setup(const ctl::ctSockaddr& targetAddress, int numReceivedBuffers, int interfaceIndex)
{
    auto lock = m_lock.lock();

    m_socket.reset(CreateDatagramSocket());
    SetSocketReceiveBufferSize(m_socket.get(), c_defaultSocketReceiveBufferSize);
    SetSocketOutgoingInterface(m_socket.get(), targetAddress.family(), interfaceIndex);
    m_receiveStates.resize(numReceivedBuffers);

    auto error = WSAConnect(m_socket.get(), targetAddress.sockaddr(), targetAddress.length(), nullptr, nullptr, nullptr, nullptr);
    THROW_LAST_ERROR_IF_MSG(SOCKET_ERROR == error, "WSAConnect failed");

    m_threadpoolIo = std::make_unique<ctl::ctThreadIocp>(m_socket.get());
}

void MeasuredSocket::Cancel() noexcept
{
    // Ensure the socket is torn down and wait for all callbacks
    {
        const auto lock = m_lock.lock();
        m_adapterStatus = AdapterStatus::Disabled;
        m_socket.reset();
    }
    m_threadpoolIo.reset();
}

void MeasuredSocket::PrepareToReceivePing(wil::shared_event pingReceived)
{
    auto lock = m_lock.lock();
    if (!m_socket.is_valid())
    {
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "Invalid socket");
    }

    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = m_receiveStates[0].m_buffer.data();
    wsabuf.len = static_cast<ULONG>(m_receiveStates[0].m_buffer.size());

    auto callback = [pingReceived, this](OVERLAPPED* ov) noexcept {
        auto lock = m_lock.lock();
        if (!m_socket.is_valid())
        {
            Log<LogLevel::Info>("Ping reception callback canceled\n");
            return;
        }

        DWORD bytesTransferred = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(m_socket.get(), ov, &bytesTransferred, false, &flags))
        {
            FAIL_FAST_LAST_ERROR_MSG("A ping receive operation failed on socket %zu", m_socket.get());
        }

        Log<LogLevel::Info>("Received a ping answer on socket %zu\n", m_socket.get());
        pingReceived.SetEvent();
    };

    DWORD bytesTransferred = 0;
    OVERLAPPED* ov = m_threadpoolIo->new_request(callback);

    Log<LogLevel::All>("Initiating a ping receive on socket %zu\n", m_socket.get());

    auto error = WSARecv(m_socket.get(), &wsabuf, 1, &bytesTransferred, &flags, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            m_threadpoolIo->cancel_request(ov);
            THROW_WIN32_MSG(error, "Failed to initiate a ping receive on socket %zu", m_socket.get());
        }
    }
}

void MeasuredSocket::PingEchoServer()
{
    auto lock = m_lock.lock();
    if (!m_socket.is_valid())
    {
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "Invalid socket");
    }

    Log<LogLevel::Info>("Sending a ping on socket %zu\n", m_socket.get());

    const auto sequenceNumber = -1;
    DatagramSendRequest sendRequest{sequenceNumber, s_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();

    // Synchronous send
    DWORD transmitedBytes = 0;
    auto error = WSASend(m_socket.get(), buffers.data(), static_cast<DWORD>(buffers.size()), &transmitedBytes, 0, nullptr, nullptr);
    THROW_LAST_ERROR_IF_MSG(SOCKET_ERROR == error, "Failed to send a ping");
}

void MeasuredSocket::CheckConnectivity()
{
    wil::shared_event connectedEvent(wil::EventOptions::ManualReset);

    PrepareToReceivePing(connectedEvent);

    // Re-send a ping immediately if the network status changes
    using winrt::Windows::Networking::Connectivity::NetworkInformation;
    auto revokeToken =
        NetworkInformation::NetworkStatusChanged(winrt::auto_revoke, [this](const auto&) { PingEchoServer(); });

    // Check connectivity
    const auto maxPingAttempts = 2;
    for (auto i = 0; i < maxPingAttempts; ++i)
    {
        PingEchoServer();

        // Wait 10sec for the answer, return false on timeout
        if (connectedEvent.wait(10000))
        {
            Log<LogLevel::Info>("Connectivity to the server confirmed on socket %zu\n", m_socket.get());
            return;
        }
    }

    Log<LogLevel::Info>("Could not reach the server on socket %zu\n", m_socket.get());
    THROW_WIN32_MSG(ERROR_NOT_CONNECTED, "Could not reach the server on socket %zu", m_socket.get());
}

void MeasuredSocket::SendDatagram(long long sequenceNumber, std::function<void(const SendResult&)> clientCallback) noexcept
{
    auto lock = m_lock.lock();
    if (!m_socket.is_valid())
    {
        Log<LogLevel::Error>("Invalid socket, ignoring send request\n");
        return;
    }

    DatagramSendRequest sendRequest{sequenceNumber, s_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();
    const MeasuredSocket::SendResult sendState{sequenceNumber, sendRequest.GetQpc()};

    Log<LogLevel::All>("Sending sequence number %lld on socket %zu\n", sequenceNumber, m_socket.get());

    auto callback = [clientCallback = std::move(clientCallback), this, sendState](OVERLAPPED* ov) noexcept {
        try
        {
            auto lock = m_lock.lock();

            if (!m_socket.is_valid())
            {
                Log<LogLevel::Info>("Send callback canceled\n");
                return;
            }

            DWORD bytesTransmitted = 0;
            DWORD flags = 0;
            if (WSAGetOverlappedResult(m_socket.get(), ov, &bytesTransmitted, false, &flags))
            {
                clientCallback(sendState);
            }
            else
            {
                Log<LogLevel::Error>("The send operation failed: %u\n", WSAGetLastError());
            }
        }
        CATCH_FAIL_FAST_MSG("Unhandled exception in send completion callback");
    };

    OVERLAPPED* ov = m_threadpoolIo->new_request(callback);

    auto error = WSASend(m_socket.get(), buffers.data(), static_cast<DWORD>(buffers.size()), nullptr, 0, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "Failed to initiate a send operation");
        }
    }
}

void MeasuredSocket::PrepareToReceive(std::function<void(ReceiveResult&)> clientCallback) noexcept
{
    for (auto& s : m_receiveStates)
    {
        PrepareToReceiveDatagram(s, clientCallback);
    }
}

void MeasuredSocket::PrepareToReceiveDatagram(ReceiveState& receiveState, std::function<void(ReceiveResult&)> clientCallback) noexcept
{
    auto lock = m_lock.lock();

    if (!m_socket.is_valid())
    {
        Log<LogLevel::Error>("Invalid socket\n");
        return;
    }

    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = receiveState.m_buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveState.m_buffer.size());

    auto callback = [this, &receiveState, clientCallback = std::move(clientCallback)](OVERLAPPED* ov) noexcept {
        try
        {
            const auto receiveTimestamp = SnapQpcInMicroSec();

            auto lock = m_lock.lock();

            if (!m_socket.is_valid())
            {
                Log<LogLevel::Info>("Receive callback canceled\n");
                return;
            }

            DWORD bytesTransferred = 0;
            DWORD flags = 0;
            if (!WSAGetOverlappedResult(m_socket.get(), ov, &bytesTransferred, false, &flags))
            {
                FAIL_FAST_LAST_ERROR_MSG("A receive operation failed");
            }

            FAIL_FAST_IF_MSG(!ValidateBufferLength(bytesTransferred), "Received an invalid message");

            const auto& header = ParseDatagramHeader(receiveState.m_buffer.data());
            Log<LogLevel::All>("Received sequence number %lld on socket %zu\n", header.m_sequenceNumber, m_socket.get());

            ReceiveResult result = {
                .m_sequenceNumber{header.m_sequenceNumber},
                .m_sendTimestamp{header.m_sendTimestamp},
                .m_receiveTimestamp{receiveTimestamp},
                .m_echoTimestamp{header.m_echoTimestamp}};
            clientCallback(result);

            PrepareToReceiveDatagram(receiveState, std::move(clientCallback));
        }
        CATCH_FAIL_FAST_MSG("Unhandled exception in send completion callback");
    };

    Log<LogLevel::All>("Initiating receive operation on socket %zu\n", m_socket.get());

    DWORD bytesTransferred = 0;
    OVERLAPPED* ov = m_threadpoolIo->new_request(callback);
    auto error = WSARecv(m_socket.get(), &wsabuf, 1, &bytesTransferred, &flags, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "Failed to initiate a receive operation");
        }
    }
}

} // namespace multipath