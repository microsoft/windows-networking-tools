#pragma once

#include <stdio.h>
#include <utility>

enum class LogLevel
{
    Output,
    Dualsta,
    Error,
    Info,
    Debug,
    All
};

LogLevel GetLogLevel() noexcept;
void SetLogLevel(LogLevel level) noexcept;

template <LogLevel L, typename... T>
void Log(const char* format, T... args)
{
    if (L <= GetLogLevel())
    {
        try
        {
            ::printf_s(format, std::forward<T>(args)...);
        }
        catch (...)
        {
        }
    }
}

template <LogLevel L, typename... T>
void Log(const wchar_t* format, T... args)
{
    if (L <= GetLogLevel())
    {
        try
        {
            ::wprintf_s(format, std::forward<T>(args)...);
        }
        catch (...)
        {
        }
    }
}