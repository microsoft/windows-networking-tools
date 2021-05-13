// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <Windows.h>
#include <functional>

#include <wil/result.h>

#include "time_utils.h"

namespace multipath {

using ThreadpoolTimerCallback = std::function<void()>;

class ThreadpoolTimer
{
public:
    explicit ThreadpoolTimer(ThreadpoolTimerCallback callback, PTP_CALLBACK_ENVIRON ptpEnv = nullptr) :
        m_callback(std::move(callback))
    {
        m_ptpTimer = CreateThreadpoolTimer(TimerCallback, this, ptpEnv);
        THROW_LAST_ERROR_IF_MSG(!m_ptpTimer, "CreateThreadpoolTimer failed");
    }

    ~ThreadpoolTimer() noexcept
    {
        m_exiting = true;
        Stop();

        WaitForThreadpoolTimerCallbacks(m_ptpTimer, true);
        CloseThreadpoolTimer(m_ptpTimer);
    }
    ThreadpoolTimer(const ThreadpoolTimer&) = delete;
    ThreadpoolTimer& operator=(const ThreadpoolTimer&) = delete;
    ThreadpoolTimer(ThreadpoolTimer&&) = delete;
    ThreadpoolTimer& operator=(ThreadpoolTimer&&) = delete;

    void Schedule(unsigned long periodInHundredNanosec) noexcept
    {
        m_exiting = false;
        m_period = periodInHundredNanosec;
        m_timerExpiration = SnapSystemTimeInHundredNs();

        FILETIME expiration{};
        SetThreadpoolTimer(m_ptpTimer, &expiration, 0, 0);
    }

    void Stop() noexcept
    {
        m_exiting = true;
        if (m_ptpTimer)
        {
            SetThreadpoolTimer(m_ptpTimer, nullptr, 0, 0);
        }
    }

private:

    void ScheduleNextPeriod() noexcept
    {
        // Don't schedule a next period if the callback (or someone else) called stop
        if (m_exiting)
        {
            return;
        }

        m_timerExpiration += m_period;
        const long long remainingTime = max(0, m_timerExpiration - SnapSystemTimeInHundredNs());

        // We are late! Call the next callback immediately
        if (remainingTime <= 0)
        {
            TimerCallback(nullptr, this, nullptr);
        }
        else
        {
            FILETIME expiration = ConvertHundredNsToRelativeFiletime(remainingTime);
            SetThreadpoolTimer(m_ptpTimer, &expiration, 0, 0);
        }
    }

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

        // Schedule the next period manually to ensure the callbacks run sequentially
        self->ScheduleNextPeriod();
    }

    std::atomic_bool m_exiting = false;
    PTP_TIMER m_ptpTimer = nullptr;
    long long m_timerExpiration{};
    unsigned long m_period = 0;
    ThreadpoolTimerCallback m_callback{};
};

} // namespace multipath