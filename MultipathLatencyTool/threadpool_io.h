#pragma once

#include <Windows.h>
#include <WinSock2.h>

#include <functional>

#include <wil/result.h>

namespace multipath {

using ThreadpoolIoCallback = std::function<void(OVERLAPPED*)>;

struct ThreadpoolIoCallbackInfo
{
    OVERLAPPED ov{};
    PVOID padding{};
    ThreadpoolIoCallback callback{};

    explicit ThreadpoolIoCallbackInfo(ThreadpoolIoCallback&& _callback) : callback(std::move(_callback))
    {
        ZeroMemory(&ov, sizeof(OVERLAPPED));
    }

    ~ThreadpoolIoCallbackInfo() = default;

    ThreadpoolIoCallbackInfo(const ThreadpoolIoCallbackInfo&) = delete;
    ThreadpoolIoCallbackInfo& operator=(const ThreadpoolIoCallbackInfo&) = delete;
    ThreadpoolIoCallbackInfo(ThreadpoolIoCallbackInfo&&) = delete;
    ThreadpoolIoCallbackInfo& operator=(ThreadpoolIoCallbackInfo&&) = delete;
};
static_assert(sizeof(ThreadpoolIoCallbackInfo) == sizeof(OVERLAPPED) + sizeof(PVOID) + sizeof(ThreadpoolIoCallback));

class ThreadpoolIo
{
public:
    explicit ThreadpoolIo(SOCKET socket, PTP_CALLBACK_ENVIRON ptpEnv = nullptr)
    {
        m_ptpIo = CreateThreadpoolIo(reinterpret_cast<HANDLE>(socket), IoCompletionCallback, nullptr, ptpEnv);
        THROW_LAST_ERROR_IF_MSG(!m_ptpIo, "CreateThreadpoolIo failed");
    }

    ~ThreadpoolIo() noexcept
    {
        if (m_ptpIo)
        {
            WaitForThreadpoolIoCallbacks(m_ptpIo, TRUE);
            CloseThreadpoolIo(m_ptpIo);
        }
    }

    ThreadpoolIo(const ThreadpoolIo&) = delete;
    ThreadpoolIo& operator=(const ThreadpoolIo&) = delete;

    ThreadpoolIo(ThreadpoolIo&& other) noexcept : m_ptpIo(other.m_ptpIo)
    {
        other.m_ptpIo = nullptr; // we now own the IO
    }

    ThreadpoolIo& operator=(ThreadpoolIo&& other) noexcept
    {
        m_ptpIo = other.m_ptpIo;
        other.m_ptpIo = nullptr; // we now own the IO
        return *this;
    }

    OVERLAPPED* NewRequest(ThreadpoolIoCallback callback) const
    {
        auto* callbackInfo = new ThreadpoolIoCallbackInfo(std::move(callback)); // can throw under low-memory situations

        StartThreadpoolIo(m_ptpIo);
        return &callbackInfo->ov;
    }

    void CancelRequest(OVERLAPPED* ov) const noexcept
    {
        CancelThreadpoolIo(m_ptpIo);
        const auto* const oldRequest = reinterpret_cast<ThreadpoolIoCallbackInfo*>(ov);
        delete oldRequest;
    }

private:
    static void CALLBACK IoCompletionCallback(
        PTP_CALLBACK_INSTANCE /*instance*/, PVOID /*context*/, PVOID overlapped, ULONG /*ioResult*/, ULONG_PTR /*numberOfBytesTransferred*/, PTP_IO /*ptpIo*/) noexcept
    {
        try
        {
            auto* info = static_cast<ThreadpoolIoCallbackInfo*>(overlapped);
            info->callback(&info->ov);
            delete info;
        }
        catch (...)
        {
            // immediately break if we catch an exception
            FAIL_FAST_MSG("exception raised in IO completion routine");
        }
    }

    PTP_IO m_ptpIo = nullptr;
};
} // namespace multipath