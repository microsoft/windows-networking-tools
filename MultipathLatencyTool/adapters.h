#pragma once

#include <vector>

namespace multipath {
std::vector<int> GetConnectedWlanInterfaces(HANDLE wlanHandle);
}