#include "stream_client.h"
#include "socket_utils.h"
#include "datagram.h"
#include "debug.h"

#include <wil/result.h>

#include <iostream>

namespace multipath {
    namespace {
        // calculates the interval at which to set the timer callback to send data at the specified rate (in bits per second)
        long long CalculateTickInterval(long long bitRate, long long frameRate, unsigned long long datagramSize) noexcept
        {
            const long long byteRate = bitRate / 8;
            const long long datagramRate = byteRate * frameRate / static_cast<long long>(datagramSize);

            // now we need to determine how often the timer should tick (in 100 nanos increments)
            long long interval = 1'000'000LL;
            FAIL_FAST_IF_MSG(datagramRate > interval, "datagram send rate higher than the available tick interval");

            return static_cast<long long>(interval / datagramRate);
        }

        long long CalculateFinalSequenceNumber(long long duration, long long bitRate, long long frameRate, unsigned long long datagramSize) noexcept
        {
            const long long byteRate = bitRate / 8;
            const long long datagramRate = byteRate * frameRate / static_cast<long long>(datagramSize);

            return static_cast<long long>(datagramRate * duration);
        }

    } // namespace

    StreamClient::StreamClient(const Sockaddr& _targetAddress, int _primaryInterfaceIndex, int _secondaryInterfaceIndex, HANDLE _completeEvent) :
        m_targetAddress(_targetAddress), m_completeEvent(_completeEvent)
    {
        constexpr DWORD DefaultSocketReceiveBufferSize = 1048576; // 1MB receive buffer

        m_primaryState.socket.reset(CreateDatagramSocket());
        m_primaryState.interface = Interface::Primary;
        m_primaryState.interfaceIndex = _primaryInterfaceIndex;
        SetSocketReceiveBufferSize(m_primaryState.socket.get(), DefaultSocketReceiveBufferSize);
        SetSocketOutgoingInterface(m_primaryState.socket.get(), m_targetAddress.family(), m_primaryState.interfaceIndex);

        PRINT_DEBUG_INFO(
            "\tStreamClient::StreamClient - created primary socket bound to interface index %d\n",
            m_primaryState.interfaceIndex);

        m_primaryState.connectEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!m_primaryState.connectEvent)
        {
            THROW_WIN32_MSG(GetLastError(), "CreateEvent (primary) failed");
        }

        m_primaryState.threadpoolIo = std::make_unique<ThreadpoolIo>(m_primaryState.socket.get());

        m_secondaryState.socket.reset(CreateDatagramSocket());
        m_secondaryState.interface = Interface::Secondary;
        m_secondaryState.interfaceIndex = _secondaryInterfaceIndex;
        SetSocketReceiveBufferSize(m_secondaryState.socket.get(), DefaultSocketReceiveBufferSize);
        SetSocketOutgoingInterface(m_secondaryState.socket.get(), m_targetAddress.family(), m_secondaryState.interfaceIndex);

        PRINT_DEBUG_INFO(
            "\tStreamClient::StreamClient - created secondary socket bound to interface index %d\n",
            m_secondaryState.interfaceIndex);

        m_secondaryState.connectEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!m_secondaryState.connectEvent)
        {
            THROW_WIN32_MSG(GetLastError(), "CreateEvent (secondary) failed");
        }

        m_secondaryState.threadpoolIo = std::make_unique<ThreadpoolIo>(m_secondaryState.socket.get());

        m_threadpoolTimer = std::make_unique<ThreadpoolTimer>([this]() noexcept { TimerCallback(); });
    }

    StreamClient::~StreamClient()
    {
    }

    void StreamClient::Start(unsigned long prePostRecvs, unsigned long sendBitRate, unsigned long sendFrameRate, unsigned long duration)
    {
        PRINT_DEBUG_INFO("\tStreamClient::Start - number of pre-posted receives is %lu\n", prePostRecvs);

        // allocate our receive contexts
        m_primaryState.receiveStates.resize(prePostRecvs);
        m_secondaryState.receiveStates.resize(prePostRecvs);

        // initialize our send buffer
        for (size_t i = 0u; i < SendBufferSize / 2; ++i)
        {
            *reinterpret_cast<unsigned short*>(&m_sharedSendBuffer[i * 2]) = static_cast<unsigned short>(i);
        }

        m_frameRate = sendFrameRate;
        const auto tickInterval = CalculateTickInterval(sendBitRate, sendFrameRate, SendBufferSize);
        m_tickInterval = ConvertHundredNanosToRelativeFiletime(tickInterval);
        m_finalSequenceNumber = CalculateFinalSequenceNumber(duration, sendBitRate, sendFrameRate, SendBufferSize);

        PRINT_DEBUG_INFO("\tStreamClient::Start - tick interval is %lld\n", tickInterval);
        PRINT_DEBUG_INFO("\tStreamClient::Start - final sequence number is %lld\n", m_finalSequenceNumber);

        // allocate statistics buffer
        FAIL_FAST_IF_MSG(m_finalSequenceNumber > MAXSIZE_T, "Final sequence number exceeds limit of vector storage");
        m_latencyStatistics.resize(static_cast<size_t>(m_finalSequenceNumber));

        // connect to target on both sockets
        PRINT_DEBUG_INFO("\tStreamClient::Start - initiating connect on both sockets\n");
        Connect(m_primaryState);
        Connect(m_secondaryState);

        bool initiateIo = false;

        HANDLE events[2] = { m_primaryState.connectEvent, m_secondaryState.connectEvent };
        auto result = WaitForMultipleObjects(2, events, TRUE, 2000); // 2 second delay for connect to complete
        switch (result)
        {
        case WAIT_OBJECT_0:
            [[fallthrough]];
        case WAIT_OBJECT_0 + 1:
            initiateIo = true;
            break;

        case WAIT_TIMEOUT:
            THROW_WIN32_MSG(ERROR_TIMEOUT, "Timed out waiting for connect to complete on both sockets");

        default:
            FAIL_FAST_WIN32_MSG(GetLastError(), "WaitForMultipleObjects failed");
        }

        if (initiateIo)
        {
            PRINT_DEBUG_INFO("\tStreamClient::Start - connected on both sockets\n");

            PRINT_DEBUG_INFO("\tStreamClient::Start - start posting receives\n");
            // initiate receives before starting the send timer
            for (auto& receiveState : m_primaryState.receiveStates)
            {
                InitiateReceive(m_primaryState, receiveState);
            }
            for (auto& receiveState : m_secondaryState.receiveStates)
            {
                InitiateReceive(m_secondaryState, receiveState);
            }

            // start sends
            PRINT_DEBUG_INFO("\tStreamClient::Start - scheduling timer callback\n");
            m_threadpoolTimer->Schedule(m_tickInterval);
        }
    }

    void StreamClient::Stop()
    {
        m_stopCalled = true;

        PRINT_DEBUG_INFO("\tStreamClient::Stop - cancelling timer callback\n");
        m_threadpoolTimer->Stop();

        PRINT_DEBUG_INFO("\tStreamClient::Stop - closing sockets\n");
        auto primaryLock = m_primaryState.csSocket.lock();
        m_primaryState.socket.reset();

        auto secondaryLock = m_secondaryState.csSocket.lock();
        m_secondaryState.socket.reset();
    }

    void StreamClient::PrintStatistics()
    {
        // simple average of latencies for received datagrams
        long long primaryLatencyTotal = 0;
        long long secondaryLatencyTotal = 0;

        long long primaryLatencySamples = 0;
        long long secondaryLatencySamples = 0;

        long long primaryLostFrames = 0;
        long long secondaryLostFrames = 0;

        for (auto i = 0u; i < m_latencyStatistics.size(); ++i)
        {
            auto const& stat = m_latencyStatistics[i];
            if (stat.sequenceNumber > 0)
            {
                if (stat.primaryLatencyMs > 0)
                {
                    primaryLatencyTotal += stat.primaryLatencyMs;
                    primaryLatencySamples += 1;
                }
                else
                {
                    primaryLostFrames += 1;
                }

                if (stat.secondaryLatencyMs > 0)
                {
                    secondaryLatencyTotal += stat.secondaryLatencyMs;
                    secondaryLatencySamples += 1;
                }
                else
                {
                    secondaryLostFrames += 1;
                }
            }
        }

        std::cout << '\n';
        std::cout << "Sent frames on primary interface: " << m_primaryState.sentFrames << '\n';
        std::cout << "Sent frames on secondary interface: " << m_secondaryState.sentFrames << '\n';

        std::cout << '\n';
        std::cout << "Received frames on primary interface: " << m_primaryState.receivedFrames << '\n';
        std::cout << "Received frames on secondary interface: " << m_secondaryState.receivedFrames << '\n';

        std::cout << '\n';
        std::cout << "Average latency on primary interface: " << primaryLatencyTotal / primaryLatencySamples << '\n';
        std::cout << "Average latency on secondary interface: " << secondaryLatencyTotal / secondaryLatencySamples << '\n';

        std::cout << '\n';
        std::cout << "Lost frames on primary interface: " << primaryLostFrames << '\n';
        std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << '\n';

        std::cout << '\n';
        std::cout << "Corrupt frames on primary interface: " << m_primaryState.corruptFrames << '\n';
        std::cout << "Corrupt frames on secondary interface: " << m_secondaryState.corruptFrames << '\n';
    }

    void StreamClient::Connect(SocketState& socketState)
    {
        // simulate a connect call so that our sockets become bound to their respective interface's IP addresses

        // start message
        WSABUF wsabuf{};
        wsabuf.buf = const_cast<char*>(START_MESSAGE);
        wsabuf.len = START_MESSAGE_LENGTH;

        PRINT_DEBUG_INFO("\tStreamClient::Connect - sending start message on %s socket\n",
            socketState.interface == Interface::Primary ? "primary" : "secondary");

        DWORD bytesTransferred = 0;
        auto error = WSASendTo(
            socketState.socket.get(), &wsabuf, 1, &bytesTransferred, 0, m_targetAddress.sockaddr(), m_targetAddress.length(), nullptr, nullptr);
        if (SOCKET_ERROR == error)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "WSASendTo failed");
        }

        // since the server will echo this message back, we also post a receive to confirm the connection and discard the response

        static int targetAddressLength = m_targetAddress.length();

        auto& receiveBuffer = socketState.receiveStates[0].buffer; // just use the first receive buffer

        WSABUF recvWsabuf{};
        recvWsabuf.buf = receiveBuffer.data();
        recvWsabuf.len = static_cast<ULONG>(receiveBuffer.size());

        OVERLAPPED* ov = socketState.threadpoolIo->NewRequest([this, &_socketState = socketState](OVERLAPPED* ov) noexcept {
            DWORD bytesTransferred = 0; // unused
            DWORD flags = 0; // unused
            if (!WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesTransferred, FALSE, &flags))
            {
                FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSAGetOverlappedResult failed");
            }

            if (!SetEvent(_socketState.connectEvent))
            {
                FAIL_FAST_WIN32_MSG(GetLastError(), "SetEvent failed");
            }

            PRINT_DEBUG_INFO(
                "\tStreamClient::Connect [callback] - successfully received echo'd start message on %s socket\n",
                _socketState.interface == Interface::Primary ? "primary" : "secondary");
            });

        DWORD flags = 0;
        error = WSARecvFrom(
            socketState.socket.get(), &recvWsabuf, 1, nullptr, &flags, m_targetAddress.sockaddr(), &targetAddressLength, ov, nullptr);
        if (SOCKET_ERROR == error)
        {
            error = WSAGetLastError();
            if (WSA_IO_PENDING != error)
            {
                THROW_WIN32_MSG(WSAGetLastError(), "WSARecvFrom failed");
            }
        }
        else
        {
            // IO completed synchronously
            if (!SetEvent(socketState.connectEvent))
            {
                FAIL_FAST_WIN32_MSG(GetLastError(), "SetEvent failed");
            }

            PRINT_DEBUG_INFO(
                "\tStreamClient::Connect - successfully received echo'd start message on %s socket\n",
                socketState.interface == Interface::Primary ? "primary" : "secondary");
        }
    }

    void StreamClient::TimerCallback() noexcept
    {
        PRINT_DEBUG_INFO("\tStreamClient::TimerCallback - timer triggered\n");

        for (auto i = 0; i < m_frameRate; ++i)
        {
            SendDatagrams();
        }

        // requeue the timer
        if (m_sequenceNumber < m_finalSequenceNumber)
        {
            PRINT_DEBUG_INFO("\tStreamClient::TimerCallback - rescheduling timer\n");
            m_threadpoolTimer->Schedule(m_tickInterval);
        }
        else
        {
            PRINT_DEBUG_INFO("\tStreamClient::TimerCallback - final sequence number sent, cancelling timer callback\n");

            FAIL_FAST_IF_MSG(m_sequenceNumber > m_finalSequenceNumber, "FATAL: Exceeded the expected number of packets sent");

            m_threadpoolTimer->Stop();

            SetEvent(m_completeEvent);
        }
    }

    void StreamClient::SendDatagrams() noexcept
    {
        if (m_stopCalled)
        {
            return;
        }

        if (m_whichFirst == Interface::Primary)
        {
            SendDatagram(m_primaryState);
            SendDatagram(m_secondaryState);
            m_whichFirst = Interface::Secondary;
        }
        else
        {
            SendDatagram(m_secondaryState);
            SendDatagram(m_primaryState);
            m_whichFirst = Interface::Primary;
        }

        m_sequenceNumber += 1;
    }

    void StreamClient::SendDatagram(SocketState& socketState) noexcept
    {
        auto lock = socketState.csSocket.lock();
        if (!socketState.socket.is_valid())
        {
            PRINT_DEBUG_INFO("\tStreamClient::SendDatagram - invalid socket, ignoring send request\n");
            return;
        }

        DatagramSendRequest sendRequest{ m_sequenceNumber, m_sharedSendBuffer.data(), m_sharedSendBuffer.size() };

        auto& buffers = sendRequest.GetBuffers();

        SendState sendState{ m_sequenceNumber, sendRequest.GetQpc() };

        PRINT_DEBUG_INFO(
            "\tStreamClient::SendDatagram - sending sequence number %lld on %s socket\n",
            m_sequenceNumber,
            socketState.interface == Interface::Primary ? "primary" : "secondary");

        auto callback = [this, &_socketState = socketState, _sendState = sendState](OVERLAPPED* ov) noexcept {
            try
            {
                auto lock = _socketState.csSocket.lock();

                if (m_stopCalled || !_socketState.socket.is_valid())
                {
                    PRINT_DEBUG_INFO("Shutting down or socket is no longer valid, ignoring send completion\n");
                    return;
                }

                DWORD bytesTransmitted = 0;
                DWORD flags = 0;
                if (WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesTransmitted, FALSE, &flags))
                {
                    SendCompletion(_socketState, _sendState);
                }
            }
            catch (...)
            {
                FAIL_FAST_CAUGHT_EXCEPTION_MSG("FATAL: Unhandled exception in send completion callback");
            }
        };

        OVERLAPPED* ov = socketState.threadpoolIo->NewRequest(callback);

        auto error = WSASendTo(
            socketState.socket.get(),
            buffers.data(),
            static_cast<DWORD>(buffers.size()),
            nullptr,
            0,
            m_targetAddress.sockaddr(),
            m_targetAddress.length(),
            ov,
            nullptr);
        if (SOCKET_ERROR == error)
        {
            error = WSAGetLastError();
            if (WSA_IO_PENDING != error)
            {
                socketState.threadpoolIo->CancelRequest(ov);
                FAIL_FAST_WIN32_MSG(error, "WSASendTo failed");
            }
        }
    }

    void StreamClient::SendCompletion(SocketState& socketState, const SendState& sendState) noexcept
    {
        socketState.sentFrames += 1;

        FAIL_FAST_IF_MSG(sendState.sequenceNumber > MAXSIZE_T, "FATAL: received sequence number out of bounds of vector");
        auto& stat = m_latencyStatistics[static_cast<size_t>(sendState.sequenceNumber)];

        stat.sequenceNumber = sendState.sequenceNumber;
        if (socketState.interface == Interface::Primary)
        {
            stat.primarySendQpc = sendState.qpc;
        }
        else
        {
            stat.secondarySendQpc = sendState.qpc;
        }
    }

    void StreamClient::InitiateReceive(SocketState& socketState, ReceiveState& receiveState)
    {
        auto lock = socketState.csSocket.lock();

        if (m_stopCalled || !socketState.socket.is_valid())
        {
            return;
        }

        receiveState.remoteAddressLen = receiveState.remoteAddress.length();

        DWORD flags = 0;

        WSABUF wsabuf;
        wsabuf.buf = receiveState.buffer.data();
        wsabuf.len = static_cast<ULONG>(receiveState.buffer.size());

        auto callback = [this, &_socketState = socketState, &_receiveState = receiveState](OVERLAPPED* ov) noexcept {
            _receiveState.qpc = SnapQpc();

            auto lock = _socketState.csSocket.lock();

            if (m_stopCalled || !_socketState.socket.is_valid())
            {
                PRINT_DEBUG_INFO("\tStreamClient::InitiateReceive [callback] - Shutting down or socket is no longer valid, "
                    "ignoring receive completion\n");
                return;
            }

            DWORD bytesTransferred = 0;
            DWORD flags = 0;
            if (!WSAGetOverlappedResult(_socketState.socket.get(), ov, &bytesTransferred, FALSE, &flags))
            {
                FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSAGetOverlappedResult (receive) failed");
            }

            ReceiveCompletion(_socketState, _receiveState, bytesTransferred);

            InitiateReceive(_socketState, _receiveState);
        };

        DWORD bytesTransferred = 0;
        OVERLAPPED* ov = socketState.threadpoolIo->NewRequest(callback);

        auto error = WSARecvFrom(
            socketState.socket.get(),
            &wsabuf,
            1,
            &bytesTransferred,
            &flags,
            receiveState.remoteAddress.sockaddr(),
            &receiveState.remoteAddressLen,
            ov,
            nullptr);
        if (SOCKET_ERROR == error)
        {
            error = WSAGetLastError();
            if (WSA_IO_PENDING != error)
            {
                socketState.threadpoolIo->CancelRequest(ov);
                FAIL_FAST_WIN32_MSG(error, "WSARecvFrom failed");
            }
        }
    }

    void StreamClient::ReceiveCompletion(SocketState& socketState, ReceiveState& receiveState, DWORD messageSize) noexcept
        try
    {
        FAIL_FAST_IF_MSG(!ValidateBufferLength(receiveState.buffer.data(), receiveState.buffer.size(), messageSize), "Received invalid message");

        auto header = ExtractDatagramHeaderFromBuffer(receiveState.buffer.data(), messageSize);

        PRINT_DEBUG_INFO(
            "\tStreamClient::ReceiveCompletion - received sequence number %lld on %s socket\n",
            header.sequenceNumber,
            socketState.interface == Interface::Primary ? "primary" : "secondary");

        if (header.sequenceNumber < 0 || header.sequenceNumber >= m_finalSequenceNumber)
        {
            PRINT_DEBUG_INFO("\tStreamClient::ReceiveCompletion - received corrupt frame\n");

            socketState.corruptFrames += 1;
            return;
        }

        socketState.receivedFrames += 1;

        FAIL_FAST_IF_MSG(header.sequenceNumber > MAXSIZE_T, "FATAL: received sequence number out of bounds of vector");
        auto& stat = m_latencyStatistics[static_cast<size_t>(header.sequenceNumber)];

        if (socketState.interface == Interface::Primary)
        {
            stat.primaryLatencyMs = ConvertHundredNanosToMillis(receiveState.qpc - header.qpc);
        }
        else
        {
            stat.secondaryLatencyMs = ConvertHundredNanosToMillis(receiveState.qpc - header.qpc);
        }
    }
    catch (...)
    {
        FAIL_FAST_CAUGHT_EXCEPTION_MSG("FATAL: Unhandled exception in receive completion callback");
    }

} // namespace multipath