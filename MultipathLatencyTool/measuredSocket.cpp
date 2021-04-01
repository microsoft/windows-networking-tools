#include "measuredSocket.h"

#include "adapters.h"
#include "datagram.h"
#include "logs.h"
#include "socket_utils.h"
#include "time_utils.h"

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
    FAIL_FAST_LAST_ERROR_IF_MSG(SOCKET_ERROR == error, "WSAConnect failed");

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
            Log<LogLevel::Debug>("StreamClient::PingEchoServer [callback] - The socket is no longer valid\n");
            return;
        }

        DWORD bytesTransferred = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(m_socket.get(), ov, &bytesTransferred, false, &flags))
        {
            FAIL_FAST_LAST_ERROR_MSG("WSARecv failed");
        }

        Log<LogLevel::Debug>("StreamClient::PingEchoServer [callback] - Received ping answer\n");
        pingReceived.SetEvent();
    };

    DWORD bytesTransferred = 0;
    OVERLAPPED* ov = m_threadpoolIo->new_request(callback);

    Log<LogLevel::All>("StreamClient::PingEchoServer - initiating WSARecv on socket %zu\n", m_socket.get());

    auto error = WSARecv(m_socket.get(), &wsabuf, 1, &bytesTransferred, &flags, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            m_threadpoolIo->cancel_request(ov);
            THROW_WIN32_MSG(error, "WSARecv failed");
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

    const auto sequenceNumber = -1;
    DatagramSendRequest sendRequest{sequenceNumber, s_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();

    // Synchronous send
    DWORD transmitedBytes = 0;
    auto error = WSASend(m_socket.get(), buffers.data(), static_cast<DWORD>(buffers.size()), &transmitedBytes, 0, nullptr, nullptr);
    THROW_LAST_ERROR_IF_MSG(SOCKET_ERROR == error, "WSASend failed");
}

void MeasuredSocket::CheckConnectivity()
{
    wil::shared_event connectedEvent(wil::EventOptions::ManualReset);

    PrepareToReceivePing(connectedEvent);

    // Check connectivity
    const auto maxPingAttempts = 2;
    for (auto i = 0; i < maxPingAttempts; ++i)
    {
        PingEchoServer();

        // Wait 10sec for the answer, return false on timeout
        if (connectedEvent.wait(10000))
        {
            return;
        }
    }

    THROW_WIN32_MSG(ERROR_NOT_CONNECTED, "Could not get an answer from the echo server");
}

void MeasuredSocket::SendDatagram(long long sequenceNumber, std::function<void(const SendResult&)> clientCallback) noexcept
{
    auto lock = m_lock.lock();
    if (!m_socket.is_valid())
    {
        Log<LogLevel::Error>("StreamClient::SendDatagram - invalid socket, ignoring send request\n");
        return;
    }

    DatagramSendRequest sendRequest{sequenceNumber, s_sharedSendBuffer};
    auto& buffers = sendRequest.GetBuffers();
    const MeasuredSocket::SendResult sendState{sequenceNumber, ConvertQpcToMicroSec(sendRequest.GetQpc())};

    Log<LogLevel::All>(
        "StreamClient::SendDatagram - sending sequence number %lld on socket %zu\n",
        sequenceNumber,
        m_socket.get());

    auto callback = [clientCallback = std::move(clientCallback), this, sendState](OVERLAPPED* ov) noexcept {
        try
        {
            auto lock = m_lock.lock();

            if (!m_socket.is_valid())
            {
                Log<LogLevel::Debug>(
                    "StreamClient::SendDatagram - The socket is no longer valid, ignoring send completion\n");
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
                Log<LogLevel::Error>("StreamClient::SendDatagram - WSASend failed : %u\n", WSAGetLastError());
            }
        }
        CATCH_FAIL_FAST_MSG("FATAL: Unhandled exception in send completion callback");
    };

    OVERLAPPED* ov = m_threadpoolIo->new_request(callback);

    auto error = WSASend(m_socket.get(), buffers.data(), static_cast<DWORD>(buffers.size()), nullptr, 0, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "WSASend failed");
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
        Log<LogLevel::Debug>("StreamClient::InitiateReceive - The socket is no longer valid\n");
        return;
    }

    DWORD flags = 0;
    WSABUF wsabuf;
    wsabuf.buf = receiveState.m_buffer.data();
    wsabuf.len = static_cast<ULONG>(receiveState.m_buffer.size());

    auto callback = [this, &receiveState, clientCallback = std::move(clientCallback)](OVERLAPPED* ov) noexcept {
        try
        {
            const auto receiveTimestamp = SnapQpc();

            auto lock = m_lock.lock();

            if (!m_socket.is_valid())
            {
                Log<LogLevel::Debug>(
                    "StreamClient::InitiateReceive [callback] - The socket is no longer valid, ignoring "
                    "receive completion\n");
                return;
            }

            DWORD bytesTransferred = 0;
            DWORD flags = 0;
            if (!WSAGetOverlappedResult(m_socket.get(), ov, &bytesTransferred, false, &flags))
            {
                FAIL_FAST_LAST_ERROR_MSG("WSARecv failed");
            }

            FAIL_FAST_IF_MSG(!ValidateBufferLength(bytesTransferred), "Received invalid message");

            const auto& header = ParseDatagramHeader(receiveState.m_buffer.data());
            Log<LogLevel::All>(
                "StreamClient::ReceiveCompletion - received sequence number %lld on socket %zu\n",
                header.m_sequenceNumber,
                m_socket.get());

            ReceiveResult result = {
                .m_sequenceNumber{header.m_sequenceNumber},
                .m_sendTimestamp{ConvertQpcToMicroSec(header.m_sendTimestamp)},
                .m_receiveTimestamp{ConvertQpcToMicroSec(receiveTimestamp)},
                .m_echoTimestamp{ConvertQpcToMicroSec(header.m_echoTimestamp)}}; // TODO: Remove, it doesn't make sense
            clientCallback(result);

            PrepareToReceiveDatagram(receiveState, std::move(clientCallback));
        }
        CATCH_FAIL_FAST_MSG("FATAL: Unhandled exception in send completion callback");
    };

    Log<LogLevel::All>("StreamClient::InitiateReceive - initiating WSARecv on socket %zu\n", m_socket.get());

    DWORD bytesTransferred = 0;
    OVERLAPPED* ov = m_threadpoolIo->new_request(callback);
    auto error = WSARecv(m_socket.get(), &wsabuf, 1, &bytesTransferred, &flags, ov, nullptr);
    if (SOCKET_ERROR == error)
    {
        error = WSAGetLastError();
        if (WSA_IO_PENDING != error)
        {
            m_threadpoolIo->cancel_request(ov);
            FAIL_FAST_WIN32_MSG(error, "WSARecv failed");
        }
    }
}

} // namespace multipath