#pragma once

#include <array>
#include <span>
#include <WinSock2.h>

namespace multipath {

constexpr unsigned long c_datagramSequenceNumberLength = 8;
constexpr unsigned long c_datagramTimestampLength = 8;
constexpr unsigned long c_datagramHeaderLength = c_datagramSequenceNumberLength + 2 * c_datagramTimestampLength;

inline long long SnapQpc() noexcept
{
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);

    return qpc.QuadPart;
}

struct DatagramHeader
{
    long long m_sequenceNumber;
    long long m_sendTimestamp; // QPC
    long long m_echoTimestamp; // QPC
};

static_assert(sizeof(DatagramHeader) == c_datagramHeaderLength);

class DatagramSendRequest
{
private:
    static constexpr int c_datagramSequenceNumberOffset = 0;
    static constexpr int c_datagramSendTimestampOffset = 1;
    static constexpr int c_datagramEchoTimestampOffset = 2;
    static constexpr int c_datagramPayloadOffset = 3;

public:
    ~DatagramSendRequest() = default;

    DatagramSendRequest() = delete;
    DatagramSendRequest(const DatagramSendRequest&) = delete;
    DatagramSendRequest& operator=(const DatagramSendRequest&) = delete;
    DatagramSendRequest(DatagramSendRequest&&) = delete;
    DatagramSendRequest& operator=(DatagramSendRequest&&) = delete;

    static constexpr size_t c_bufferArraySize = 4;
    using BufferArray = std::array<WSABUF, c_bufferArraySize>;

    DatagramSendRequest(long long sequenceNumber, std::span<const char> sendBuffer) : m_sequenceNumber(sequenceNumber)
    {
        static_assert(c_bufferArraySize == c_datagramPayloadOffset + 1);

        // buffer layout: sequence number, send timestamp (QPC), echo timestamp (QPC), then buffer data
        m_wsabufs[c_datagramSequenceNumberOffset].buf = reinterpret_cast<char*>(&m_sequenceNumber);
        m_wsabufs[c_datagramSequenceNumberOffset].len = c_datagramSequenceNumberLength;

        m_wsabufs[c_datagramSendTimestampOffset].buf = reinterpret_cast<char*>(&m_sendTimestamp.QuadPart);
        m_wsabufs[c_datagramSendTimestampOffset].len = c_datagramTimestampLength;

        m_wsabufs[c_datagramEchoTimestampOffset].buf = reinterpret_cast<char*>(&m_echoTimestamp.QuadPart);
        m_wsabufs[c_datagramEchoTimestampOffset].len = c_datagramTimestampLength;

        m_wsabufs[c_datagramPayloadOffset].buf = const_cast<char*>(sendBuffer.data());
        m_wsabufs[c_datagramPayloadOffset].len = static_cast<ULONG>(sendBuffer.size() - c_datagramHeaderLength);
    }

    BufferArray& GetBuffers() noexcept
    {
        // refresh QPC value at last possible moment
        // TODO: Need to convert to usable time!! Does it even make sense? Does QPC on server has the same orig?
        QueryPerformanceCounter(&m_sendTimestamp);
        return m_wsabufs;
    }

    [[nodiscard]] long long GetQpc() const noexcept
    {
        return m_sendTimestamp.QuadPart;
    }

private:
    BufferArray m_wsabufs{};
    long long m_sequenceNumber = 0;
    LARGE_INTEGER m_sendTimestamp{};
    LARGE_INTEGER m_echoTimestamp{};
};

inline bool ValidateBufferLength(size_t completedBytes) noexcept
{
    if (completedBytes < c_datagramHeaderLength)
    {
        fprintf(stderr, "ValidateBufferLength rejecting the datagram: the size (%zu) is less than DatagramHeaderLength (%lu)", completedBytes, c_datagramHeaderLength);
        return false;
    }
    return true;
}

inline DatagramHeader& ParseDatagramHeader(char* buffer) noexcept
{
    return *reinterpret_cast<DatagramHeader*>(buffer);
}

} // namespace multipath