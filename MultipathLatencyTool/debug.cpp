#include "debug.h"

namespace multipath {
static unsigned long g_consoleVerbosity = 1;
static bool g_localDebugMode = false;

unsigned long ConsoleVerbosity() noexcept
{
    return g_consoleVerbosity;
}

void SetConsoleVerbosity(unsigned long value) noexcept
{
    g_consoleVerbosity = value;
}

bool LocalDebugMode() noexcept
{
    return g_localDebugMode;
}

void SetLocalDebugMode(bool value) noexcept
{
    g_localDebugMode = value;
}
} // namespace multipath