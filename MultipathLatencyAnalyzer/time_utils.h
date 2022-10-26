// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <Windows.h>

namespace multipath {

inline long long SnapQpc() noexcept
{
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);

    return qpc.QuadPart;
}

inline long long SnapQpcInMicroSec() noexcept
{
    // snap the frequency on first call; C++11 guarantees this is thread-safe
    static const long long c_qpf = []() {
        LARGE_INTEGER qpf;
        QueryPerformanceFrequency(&qpf);
        return qpf.QuadPart;
    }();

    // (qpc / qpf) is in seconds
    return SnapQpc() * 1'000'000LL / c_qpf;
}

// Create a negative FILETIME, which for some timer APIs indicate a 'relative' time
// - e.g. SetThreadpoolTimer, where a negative value indicates the amount of time to wait relative to the current time
inline FILETIME ConvertHundredNsToRelativeFiletime(long long hundredNanoseconds) noexcept
{
    ULARGE_INTEGER ulongInteger;
    ulongInteger.QuadPart = static_cast<ULONGLONG>(-hundredNanoseconds);

    FILETIME returnFiletime;
    returnFiletime.dwHighDateTime = ulongInteger.HighPart;
    returnFiletime.dwLowDateTime = ulongInteger.LowPart;
    return returnFiletime;
}

inline long long ConvertFiletimeToHundredNs(const FILETIME& filetime) noexcept
{
    ULARGE_INTEGER ulongInteger;
    ulongInteger.HighPart = filetime.dwHighDateTime;
    ulongInteger.LowPart = filetime.dwLowDateTime;

    return ulongInteger.QuadPart;
}

inline long long SnapSystemTimeInHundredNs() noexcept
{
    FILETIME filetime;
    GetSystemTimeAsFileTime(&filetime);
    return ConvertFiletimeToHundredNs(filetime);
}

} // namespace multipath