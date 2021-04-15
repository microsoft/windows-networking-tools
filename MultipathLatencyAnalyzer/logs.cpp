#include "logs.h"

static LogLevel g_logLevel = LogLevel::Error;

LogLevel GetLogLevel() noexcept
{
    return g_logLevel;
}

void SetLogLevel(LogLevel level) noexcept
{
    g_logLevel = level;
}