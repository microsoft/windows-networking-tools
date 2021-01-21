#include "pch.h"

#include <netioapi.h>

#include "adapters.h"

using namespace winrt;
using namespace Windows::Networking::Connectivity;

namespace multipath {
std::vector<int> GetConnectedInterfaces()
{
    std::vector<int> result{};

    auto profiles = NetworkInformation::GetConnectionProfiles();
    for (auto&& profile : profiles)
    {
        auto connectivity = profile.GetNetworkConnectivityLevel();
        if (connectivity == NetworkConnectivityLevel::InternetAccess)
        {
            auto interfaceGuid = profile.NetworkAdapter().NetworkAdapterId();

            // convert to LUID then to index
            NET_LUID luid{};
            auto error = ConvertInterfaceGuidToLuid(reinterpret_cast<GUID*>(&interfaceGuid), &luid);
            THROW_IF_NTSTATUS_FAILED_MSG(error, "ConvertInterfaceGuidToLuid failed");

            NET_IFINDEX index = 0;
            error = ConvertInterfaceLuidToIndex(&luid, &index);
            THROW_IF_NTSTATUS_FAILED_MSG(error, "ConvertInterfaceLuidToIndex failed");

            result.push_back(static_cast<int>(index));
        }
    }

    return result;
}
}