#pragma once

#include <Windows.h>
#include <functional>

#include <wil/result.h>

namespace multipath {

// utility functions
constexpr long long ConvertMillisToHundredNanos(long long ms) noexcept
{
    return static_cast<long long>(ms * 10000LL);
}

constexpr long long ConvertHundredNanosToMillis(long long hundredNs) noexcept
{
    return static_cast<long long>(hundredNs / 10000LL);
}

constexpr FILETIME ConvertHundredNanosToAbsoluteFiletime(long long hundredNs) noexcept
{
    ULARGE_INTEGER value{};
    value.QuadPart = hundredNs;

    FILETIME result{};
    result.dwHighDateTime = value.HighPart;
    result.dwLowDateTime = value.LowPart;
    return result;
}

constexpr FILETIME ConvertHundredNanosToRelativeFiletime(long long hundredNs) noexcept
{
    ULARGE_INTEGER value{};
    value.QuadPart = static_cast<ULONGLONG>(-hundredNs);

    FILETIME result{};
    result.dwHighDateTime = value.HighPart;
    result.dwLowDateTime = value.LowPart;
    return result;
}

constexpr long long ConvertFiletimeToHundredNanos(FILETIME filetime) noexcept
{
    ULARGE_INTEGER result{};
    result.HighPart = filetime.dwHighDateTime;
    result.LowPart = filetime.dwLowDateTime;
    return result.QuadPart;
}

constexpr long long ConvertFiletimeToMillis(FILETIME filetime) noexcept
{
    return ConvertHundredNanosToMillis(ConvertFiletimeToHundredNanos(filetime));
}

constexpr FILETIME ConvertMillisToAbsoluteFiletime(long long ms) noexcept
{
    return ConvertHundredNanosToAbsoluteFiletime(ConvertMillisToHundredNanos(ms));
}

constexpr FILETIME ConvertMillisToRelativeFiletime(long long ms) noexcept
{
    return ConvertHundredNanosToRelativeFiletime(ConvertMillisToHundredNanos(ms));
}

inline long long SnapSystemTimeInMillis() noexcept
{
    FILETIME filetime{};
    GetSystemTimeAsFileTime(&filetime);
    return ConvertFiletimeToMillis(filetime);
}

inline long long SnapQpcInMillis() noexcept
{
    // snap the frequency on first call; C++11 guarantees this is thread-safe
    static const long long qpf = []() {
        LARGE_INTEGER _qpf;
        QueryPerformanceFrequency(&_qpf);
        return _qpf.QuadPart;
    }();

    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);

    // multiply by 1000 as (qpc / qpf) is in seconds
    return static_cast<long long>(qpc.QuadPart * 1000LL / qpf);
}

using ThreadpoolTimerCallback = std::function<void()>;

class ThreadpoolTimer
{
public:
    explicit ThreadpoolTimer(ThreadpoolTimerCallback _callback, PTP_CALLBACK_ENVIRON _ptpEnv = nullptr) : m_callback(std::move(_callback))
    {
        m_ptpTimer = CreateThreadpoolTimer(TimerCallback, this, _ptpEnv);
        THROW_LAST_ERROR_IF_MSG(!m_ptpTimer, "CreateThreadpoolTimer failed");
    }

    ~ThreadpoolTimer() noexcept
    {
        m_exiting = true;
        Stop();

        WaitForThreadpoolTimerCallbacks(m_ptpTimer, TRUE);
    }

    void Schedule(FILETIME dueTime)
    {
        SetThreadpoolTimer(m_ptpTimer, &dueTime, 0, 0);
    }

    void Stop()
    {
        if (m_ptpTimer)
        {
            SetThreadpoolTimer(m_ptpTimer, nullptr, 0, 0);
        }
    }

private:
    static void CALLBACK TimerCallback(PTP_CALLBACK_INSTANCE /*instance*/, PVOID context, PTP_TIMER /*ptpTimer*/) noexcept
    {
        auto* self = static_cast<ThreadpoolTimer*>(context);

        if (self->m_exiting)
        {
            return;
        }

        try
        {
            self->m_callback();
        }
        catch (...)
        {
            // immediately break if we catch an exception
            FAIL_FAST_MSG("exception raised in timer callback routine");
        }
    }

    bool m_exiting = false;
    PTP_TIMER m_ptpTimer = nullptr;
    ThreadpoolTimerCallback m_callback{};
};

} // namespace multipath