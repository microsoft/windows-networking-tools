#pragma once

#include <stdio.h>

namespace multipath {
unsigned long ConsoleVerbosity() noexcept;

void SetConsoleVerbosity(unsigned long value) noexcept;
} // namespace multipath

#define PRINT_DEBUG_INFO(fmt, ...) \
    do \
    { \
        if (2 == ::multipath::ConsoleVerbosity()) \
        { \
            try \
            { \
                ::printf_s(fmt, ##__VA_ARGS__); \
            } \
            catch (...) \
            { \
            } \
        } \
    } while ((void)0, 0)