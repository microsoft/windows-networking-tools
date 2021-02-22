#include "debug.h"

namespace multipath {
static unsigned long g_consoleVerbosity = 1;

unsigned long ConsoleVerbosity() noexcept
{
    return g_consoleVerbosity;
}

void SetConsoleVerbosity(unsigned long value) noexcept
{
    g_consoleVerbosity = value;
}
} // namespace multipath