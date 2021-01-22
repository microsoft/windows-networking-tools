#include "pch.h"

#include <netioapi.h>

#include "adapters.h"

using namespace winrt;
using namespace Windows::Networking::Connectivity;

namespace multipath {
wil::unique_wlan_handle OpenWlanHandle()
{
    wil::unique_wlan_handle wlanHandle;

    constexpr DWORD wlanVersion = 2; // Vista+ API
    DWORD wlanCurVersion = 0;
    auto error = WlanOpenHandle(wlanVersion, nullptr, &wlanCurVersion, &wlanHandle);
    if (ERROR_SUCCESS != error)
    {
        THROW_WIN32_MSG(error, "WlanOpenHandle failed");
    }

    return wlanHandle;
}

std::vector<GUID> GetPrimaryInterfaceGuids(HANDLE wlanHandle)
{
    std::vector<GUID> primaryInterfaces{};

    PWLAN_INTERFACE_INFO_LIST primaryInterfaceList = nullptr;
    auto error = WlanEnumInterfaces(wlanHandle, nullptr, &primaryInterfaceList);
    if (ERROR_SUCCESS != error)
    {
        THROW_WIN32_MSG(error, "WlanEnumInterfaces failed");
    }

    if (primaryInterfaceList->dwNumberOfItems < 1)
    {
        THROW_WIN32_MSG(ERROR_NOT_FOUND, "Did not find a WiFi interface");
    }

    // pick the first interface (TODO: could be better about handling multiple adapters?)
    for (auto i = 0u; i < primaryInterfaceList->dwNumberOfItems; ++i)
    {
        primaryInterfaces.push_back(primaryInterfaceList->InterfaceInfo[i].InterfaceGuid);
    }

    return primaryInterfaces;
}

void SetSecondaryInterfaceEnabled(HANDLE wlanHandle, const GUID& primaryInterfaceGuid)
{
    BOOL enable = TRUE;
    auto error = WlanSetInterface(
        wlanHandle, &primaryInterfaceGuid, wlan_intf_opcode_secondary_sta_synchronized_connections, sizeof(BOOL), static_cast<PVOID>(&enable), nullptr);
    if (ERROR_SUCCESS != error)
    {
        THROW_WIN32_MSG(error, "WlanSetInterface(wlan_intf_opcode_secondary_sta_synchronized_connections) failed");
    }
}

std::vector<GUID> GetSecondaryInterfaceGuids(HANDLE wlanHandle, const GUID& primaryInterfaceGuid)
{
    std::vector<GUID> secondaryInterfaces{};

    PWLAN_INTERFACE_INFO_LIST secondaryInterfaceList = nullptr;
    DWORD dataSize = 0;

    auto error = WlanQueryInterface(
        wlanHandle,
        &primaryInterfaceGuid,
        wlan_intf_opcode_secondary_sta_interfaces,
        nullptr,
        &dataSize,
        reinterpret_cast<PVOID*>(&secondaryInterfaceList),
        nullptr);
    if (ERROR_SUCCESS != error)
    {
        THROW_WIN32_MSG(error, "WlanQueryInterface failed");
    }

    for (auto i = 0u; i < secondaryInterfaceList->dwNumberOfItems; ++i)
    {
        secondaryInterfaces.push_back(secondaryInterfaceList->InterfaceInfo[i].InterfaceGuid);
    }

    return secondaryInterfaces;
}

struct WlanInterfaceGuids
{
    GUID primaryInterface;
    GUID secondaryInterface;
};

WlanInterfaceGuids GetWlanInterfaces(HANDLE wlanHandle)
{
    auto primaryInterfaces = GetPrimaryInterfaceGuids(wlanHandle);

    // scan the returned list for interfaces that have secondary interfaces
    // stop when we have found an adapter that supports secondary STA
    for (const auto& primaryInterface : primaryInterfaces)
    {
        SetSecondaryInterfaceEnabled(wlanHandle, primaryInterface);

        auto secondaryInterfaces = GetSecondaryInterfaceGuids(wlanHandle, primaryInterface);
        if (secondaryInterfaces.size() > 0) 
        {
            // pull the first interface from the list
            return { primaryInterface, secondaryInterfaces.front() };
        }
    }

    THROW_WIN32_MSG(ERROR_NOT_FOUND, "Unable to find WiFi adapter with Secondary STA support");
}

bool WaitForConnectedWlanInterfaces(const WlanInterfaceGuids& wlanInterfaces, DWORD msTimeout = 30 * 1000)
{
    bool primaryConnected = false;
    bool secondaryConnected = false;

    auto checkForConnected = [&]() {
        auto profiles = NetworkInformation::GetConnectionProfiles();
        for (auto const& profile : profiles)
        {
            auto interfaceGuid = profile.NetworkAdapter().NetworkAdapterId();
            if (*reinterpret_cast<GUID*>(&interfaceGuid) == wlanInterfaces.primaryInterface)
            {
                if (profile.GetNetworkConnectivityLevel() == NetworkConnectivityLevel::InternetAccess)
                {
                    primaryConnected = true;
                }
            }
            else if (*reinterpret_cast<GUID*>(&interfaceGuid) == wlanInterfaces.secondaryInterface)
            {
                if (profile.GetNetworkConnectivityLevel() == NetworkConnectivityLevel::InternetAccess)
                {
                    secondaryConnected = true;
                }
            }
        }
    };

    checkForConnected();

    // wait for both connections to become connected
    if (!primaryConnected || !secondaryConnected)
    {
        wil::unique_event event {wil::EventOptions::ManualReset};

        auto eventToken = NetworkInformation::NetworkStatusChanged([&](const auto&) {
            checkForConnected();

            if (primaryConnected && secondaryConnected)
            {
                event.SetEvent();
            }
        });

        event.wait(msTimeout);
    }

    return primaryConnected && secondaryConnected;
}

int ConvertInterfaceGuidToIndex(const GUID& interfaceGuid)
{
    NET_LUID interfaceLuid{};
    auto error = ConvertInterfaceGuidToLuid(&interfaceGuid, &interfaceLuid);
    THROW_IF_NTSTATUS_FAILED_MSG(error, "ConvertInterfaceGuidToLuid failed");

    NET_IFINDEX interfaceIndex = 0;
    error = ConvertInterfaceLuidToIndex(&interfaceLuid, &interfaceIndex);
    THROW_IF_NTSTATUS_FAILED_MSG(error, "ConvertInterfaceLuidToIndex failed");

    return static_cast<int>(interfaceIndex);
}

std::vector<int> GetConnectedWlanInterfaces(HANDLE wlanHandle)
{
    std::vector<int> result;

    auto wlanInterfaceGuids = GetWlanInterfaces(wlanHandle);
    auto connected = WaitForConnectedWlanInterfaces(wlanInterfaceGuids);

    if (connected)
    {
        // both the primary and secondary interfaces are indicated as connected
        // convert the GUIDs to interface indexes that can be set on the sockets
        result.push_back(ConvertInterfaceGuidToIndex(wlanInterfaceGuids.primaryInterface));
        result.push_back(ConvertInterfaceGuidToIndex(wlanInterfaceGuids.secondaryInterface));
    }

    return result;
}

} // namespace multipath