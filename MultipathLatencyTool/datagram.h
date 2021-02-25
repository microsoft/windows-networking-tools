#pragma once

#include <array>
#include <WinSock2.h>

namespace multipath {

constexpr const char* c_startMessage = "START";
constexpr size_t c_startMessageLength = 5; // no null terminator

constexpr unsigned long c_datagramSequenceNumberLength = 8;
constexpr unsigned long c_datagramTimestampLength = 8;
constexpr unsigned long c_datagramHeaderLength = c_datagramSequenceNumberLength + c_datagramTimestampLength;

struct DatagramHeader
{
    long long m_sequenceNumber;
    long long m_qpc;
};

class DatagramSendRequest
{
private:
    static constexpr int c_datagramSequenceNumberOffset = 0;
    static constexpr int c_datagramTimestampOffset = 1;
    static constexpr int c_datagramPayloadOffset = 2;

public:
    ~DatagramSendRequest() = default;

    DatagramSendRequest() = delete;
    DatagramSendRequest(const DatagramSendRequest&) = delete;
    DatagramSendRequest& operator=(const DatagramSendRequest&) = delete;
    DatagramSendRequest(DatagramSendRequest&&) = delete;
    DatagramSendRequest& operator=(DatagramSendRequest&&) = delete;

    static constexpr size_t c_bufferArraySize = 3;
    using BufferArray = std::array<WSABUF, c_bufferArraySize>;

    DatagramSendRequest(long long sequenceNumber, const char* sendBuffer, size_t sendBufferLength) :
        m_sequenceNumber(sequenceNumber)
    {
        // buffer layout: sequence number, timestamp (QPC), then buffer data
        m_wsabufs[c_datagramSequenceNumberOffset].buf = reinterpret_cast<char*>(&m_sequenceNumber);
        m_wsabufs[c_datagramSequenceNumberOffset].len = c_datagramSequenceNumberLength;

        m_wsabufs[c_datagramTimestampOffset].buf = reinterpret_cast<char*>(&m_qpc.QuadPart);
        m_wsabufs[c_datagramTimestampOffset].len = c_datagramTimestampLength;

        m_wsabufs[c_datagramPayloadOffset].buf = const_cast<char*>(sendBuffer);
        m_wsabufs[c_datagramPayloadOffset].len = static_cast<ULONG>(sendBufferLength - c_datagramHeaderLength);
        static_assert(c_datagramHeaderLength == c_datagramSequenceNumberLength + c_datagramTimestampLength);
    }

    BufferArray& GetBuffers() noexcept
    {
        // refresh QPC value at last possible moment
        QueryPerformanceCounter(&m_qpc);
        return m_wsabufs;
    }

    [[nodiscard]] long long GetQpc() const noexcept
    {
        return m_qpc.QuadPart;
    }

private:
    BufferArray m_wsabufs{};
    LARGE_INTEGER m_qpc{};
    long long m_sequenceNumber = 0;
};

inline bool ValidateBufferLength(const char* /*buffer*/, size_t /*bufferLength*/, size_t completedBytes) noexcept
{
    if (completedBytes < c_datagramHeaderLength)
    {
        fprintf(stderr, "ValidateBufferLength rejecting the datagram: the size (%zu) is less than DatagramHeaderLength (%lu)", completedBytes, c_datagramHeaderLength);
        return false;
    }
    return true;
}

inline DatagramHeader ExtractDatagramHeaderFromBuffer(const char* buffer, size_t /*bufferLength*/) noexcept
{
    DatagramHeader header{};

    auto error = memcpy_s(&header.m_sequenceNumber, c_datagramSequenceNumberLength, buffer, c_datagramSequenceNumberLength);
    FAIL_FAST_IF_MSG(error != 0, "ExtractDatagramHeaderFromBuffer: memcpy_s failed trying to copy the sequence number: %d", error);

    buffer += c_datagramSequenceNumberLength;
    error = memcpy_s(&header.m_qpc, c_datagramTimestampLength, buffer, c_datagramTimestampLength);
    FAIL_FAST_IF_MSG(error != 0, "ExtractDatagramHeaderFromBuffer: memcpy_s failed trying to copy the timestamp: %d", error);

    return header;
}

inline const char* ExtractDatagramPayloadFromBuffer(const char* buffer, size_t /*bufferLength*/) noexcept
{
    return buffer + c_datagramHeaderLength;
}

} // namespace multipath