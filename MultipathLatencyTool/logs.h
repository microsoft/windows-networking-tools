#pragma once

#include <stdio.h>

enum class LogLevel
{
    Output,
    Error,
    Info,
    Debug,
    All
};

LogLevel GetLogLevel() noexcept;
void SetLogLevel(LogLevel level) noexcept;

template <LogLevel L, typename ...T>
void Log(const char* format, T... args)
{
    if (L <= GetLogLevel())
    {
        try
        {
            ::printf_s(format, args...);
        }
        catch (...)
        {
        }
    }
}