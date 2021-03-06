#pragma once

#include <Windows.h>

#include <optional>

namespace multipath {
std::optional<int> GetSecondaryInterfaceBestEffort(HANDLE wlanHandle);
}