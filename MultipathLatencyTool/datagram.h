#pragma once

#include <iterator>

#include <WinSock2.h>

#include <wil/result.h>

namespace multipath {

constexpr const char* START_MESSAGE = "START";
constexpr size_t START_MESSAGE_LENGTH = 5; // no null terminator

constexpr unsigned long DatagramSequenceNumberLength = 8;
constexpr unsigned long DatagramTimestampLength = 8;
constexpr unsigned long DatagramInterfaceIndexLength = 8;
constexpr unsigned long DatagramHeaderLength = DatagramSequenceNumberLength + DatagramTimestampLength + DatagramInterfaceIndexLength;

struct DatagramHeader
{
    long long sequenceNumber;
    LARGE_INTEGER qpc;
    long long interfaceIndex;
};

class DatagramSendRequest
{
private:
    static constexpr int DatagramSequenceNumberOffset = 0;
    static constexpr int DatagramTimestampOffset = 1;
    static constexpr int DatagramInterfaceIndexOffset = 2;
    static constexpr int DatagramPayloadOffset = 3;

public:
    ~DatagramSendRequest() = default;

    DatagramSendRequest() = delete;
    DatagramSendRequest(const DatagramSendRequest&) = delete;
    DatagramSendRequest& operator=(const DatagramSendRequest&) = delete;
    DatagramSendRequest(DatagramSendRequest&&) = delete;
    DatagramSendRequest& operator=(DatagramSendRequest&&) = delete;

    static constexpr size_t BufferArraySize = 4;
    using BufferArray = std::array<WSABUF, BufferArraySize>;

    DatagramSendRequest(long long _sequenceNumber, long long _ifIndex, const char* _sendBuffer, size_t _sendBufferLength) :
        sequenceNumber(_sequenceNumber), ifIndex(_ifIndex)
    {
        // buffer layout: sequence number, timestamp (QPC), then buffer data
        wsabufs[DatagramSequenceNumberOffset].buf = reinterpret_cast<char*>(&sequenceNumber);
        wsabufs[DatagramSequenceNumberOffset].len = DatagramSequenceNumberLength;

        wsabufs[DatagramTimestampOffset].buf = reinterpret_cast<char*>(&qpc.QuadPart);
        wsabufs[DatagramTimestampOffset].len = DatagramTimestampLength;

        wsabufs[DatagramInterfaceIndexOffset].buf = reinterpret_cast<char*>(&ifIndex);
        wsabufs[DatagramInterfaceIndexOffset].len = DatagramInterfaceIndexLength;

        wsabufs[DatagramPayloadOffset].buf = const_cast<char*>(_sendBuffer);
        wsabufs[DatagramPayloadOffset].len = static_cast<ULONG>(_sendBufferLength - DatagramHeaderLength);
    }

    BufferArray& GetBuffers() noexcept
    {
        // refresh QPC value at last possible moment
        QueryPerformanceCounter(&qpc);

        return wsabufs;
    }

    long long GetQpc() noexcept
    {
        return qpc.QuadPart;
    }

private:
    BufferArray wsabufs{};
    LARGE_INTEGER qpc{};;
    long long sequenceNumber = 0;
    long long ifIndex = 0;
};

bool ValidateBufferLength(const char* /*buffer*/, size_t /*bufferLength*/, size_t completedBytes) noexcept
{
    if (completedBytes < DatagramHeaderLength)
    {
        fprintf(stderr, "ValidateBufferLength rejecting the datagram: the size (%zu) is less than DatagramHeaderLength (%u)", completedBytes, DatagramHeaderLength);
        return false;
    }
    return true;
}

DatagramHeader ExtractDatagramHeaderFromBuffer(const char* buffer, size_t /*bufferLength*/) noexcept
{
    DatagramHeader header{};

    auto error = memcpy_s(&header.sequenceNumber, DatagramSequenceNumberLength, buffer, DatagramSequenceNumberLength);
    FAIL_FAST_IF_MSG(error != 0, "ExtractDatagramHeaderFromBuffer: memcpy_s failed trying to copy the sequence number: %d", error);
    
    buffer += DatagramSequenceNumberLength;
    error = memcpy_s(&header.qpc.QuadPart, DatagramTimestampLength, buffer, DatagramTimestampLength);
    FAIL_FAST_IF_MSG(error != 0, "ExtractDatagramHeaderFromBuffer: memcpy_s failed trying to copy the timestamp: %d", error);

    buffer += DatagramTimestampLength;
    error = memcpy_s(&header.interfaceIndex, DatagramInterfaceIndexLength, buffer, DatagramInterfaceIndexLength);
    FAIL_FAST_IF_MSG(error != 0, "ExtractDatagramHeaderFromBuffer: memcpy_s failed trying to copy the interface index: %d", error);

    return header;
}

const char* ExtractDatagramPayloadFromBuffer(const char* buffer, size_t /*bufferLength*/) noexcept
{
    return buffer + DatagramHeaderLength;
}

} // namespace multipath