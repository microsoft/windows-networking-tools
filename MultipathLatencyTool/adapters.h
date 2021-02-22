#pragma once

#include <Windows.h>

#include <vector>

namespace multipath {
std::vector<int> GetConnectedWlanInterfaces(HANDLE wlanHandle);
}