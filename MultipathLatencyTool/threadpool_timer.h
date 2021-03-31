#pragma once

#include <Windows.h>
#include <functional>

#include <wil/result.h>

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

    void Schedule(FILETIME dueTime) const noexcept
    {
        SetThreadpoolTimer(m_ptpTimer, &dueTime, 0, 0);
    }

    void Stop() const noexcept
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

    std::atomic_bool m_exiting = false;
    PTP_TIMER m_ptpTimer = nullptr;
    ThreadpoolTimerCallback m_callback{};
};

} // namespace multipath