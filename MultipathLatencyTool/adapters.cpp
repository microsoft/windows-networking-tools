#include "adapters.h"
#include "debug.h"

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.Connectivity.h>

#include <wil/result.h>
#include <wil/resource.h>

#include <Windows.h>
#include <wlanapi.h>
#include <netioapi.h>

using namespace winrt;
using namespace Windows::Networking::Connectivity;

namespace multipath {
std::vector<GUID> GetPrimaryInterfaceGuids(HANDLE wlanHandle)
{
    std::vector<GUID> primaryInterfaces{};

    PWLAN_INTERFACE_INFO_LIST primaryInterfaceList = nullptr;
    const auto error = WlanEnumInterfaces(wlanHandle, nullptr, &primaryInterfaceList);
    THROW_IF_WIN32_ERROR_MSG(error, "WlanEnumInterfaces failed");

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

void EnableSecondaryInterface(HANDLE wlanHandle, const GUID& primaryInterfaceGuid)
{
    BOOL enable = TRUE;
    const auto error = WlanSetInterface(
        wlanHandle, &primaryInterfaceGuid, wlan_intf_opcode_secondary_sta_synchronized_connections, sizeof(BOOL), static_cast<PVOID>(&enable), nullptr);
    THROW_IF_WIN32_ERROR_MSG(error, "WlanSetInterface(wlan_intf_opcode_secondary_sta_synchronized_connections) failed");

    PRINT_DEBUG_INFO("\tSetSecondaryInterfaceEnabled - successfully set opcode "
                     "`wlan_intf_opcode_secondary_sta_synchronized_connections`\n");
}

std::optional<GUID> GetSecondaryInterfaceGuid(HANDLE wlanHandle, const GUID& primaryInterfaceGuid)
{
    PWLAN_INTERFACE_INFO_LIST secondaryInterfaceList = nullptr;
    DWORD dataSize = 0;

    const auto error = WlanQueryInterface(
        wlanHandle,
        &primaryInterfaceGuid,
        wlan_intf_opcode_secondary_sta_interfaces,
        nullptr,
        &dataSize,
        reinterpret_cast<PVOID*>(&secondaryInterfaceList),
        nullptr);
    THROW_IF_WIN32_ERROR_MSG(error, "WlanQueryInterface failed");

    PRINT_DEBUG_INFO("\tGetSecondaryInterfaceGuids - received %lu secondary interface GUIDs\n", secondaryInterfaceList->dwNumberOfItems);

    // There is at most one secondary interface for a primary interface
    if (secondaryInterfaceList->dwNumberOfItems > 0)
    {
        return secondaryInterfaceList->InterfaceInfo[0].InterfaceGuid;
    }
    else
    {
        return std::nullopt;
    }
}

struct WlanInterfaceGuids
{
    GUID m_primaryInterface;
    GUID m_secondaryInterface;
};

bool WaitForConnectedWlanInterfaces(const WlanInterfaceGuids& wlanInterfaces, DWORD msTimeout = 30 * 1000)
{
    bool primaryConnected = false;
    bool secondaryConnected = false;

    auto checkForConnected = [&]() {
        PRINT_DEBUG_INFO(
            "\tWaitForConnectedWlanInterfaces [callback] - checking for connected primary and secondary interfaces\n");

        auto profiles = NetworkInformation::GetConnectionProfiles();
        for (const auto& profile : profiles)
        {
            const auto interfaceGuid = profile.NetworkAdapter().NetworkAdapterId();
            if (*reinterpret_cast<const GUID*>(&interfaceGuid) == wlanInterfaces.m_primaryInterface)
            {
                PRINT_DEBUG_INFO(
                    "\tWaitForConnectedWlanInterfaces [callback] - found primary interface connection profile\n");
                if (profile.GetNetworkConnectivityLevel() == NetworkConnectivityLevel::InternetAccess)
                {
                    PRINT_DEBUG_INFO("\tWaitForConnectedWlanInterfaces [callback] - primary interface is connected\n");
                    primaryConnected = true;
                }
            }
            else if (*reinterpret_cast<const GUID*>(&interfaceGuid) == wlanInterfaces.m_secondaryInterface)
            {
                PRINT_DEBUG_INFO(
                    "\tWaitForConnectedWlanInterfaces [callback] - found secondary interface connection profile\n");
                if (profile.GetNetworkConnectivityLevel() == NetworkConnectivityLevel::InternetAccess)
                {
                    PRINT_DEBUG_INFO(
                        "\tWaitForConnectedWlanInterfaces [callback] - secondary interface is connected\n");
                    secondaryConnected = true;
                }
            }
        }
    };

    checkForConnected();

    // wait for both connections to become connected
    if (!primaryConnected || !secondaryConnected)
    {
        wil::unique_event event{wil::EventOptions::ManualReset};

        PRINT_DEBUG_INFO("\tWaitForConnectedWlanInterfaces - one or more interfaces not yet connected, registering for "
                         "network change notifications\n");

        // by passing winrt::auto_revoke and storing the result, we will be automatically
        // unsubscribed when this object goes out of scope
        auto eventRevoker = NetworkInformation::NetworkStatusChanged(winrt::auto_revoke, [&](const auto&) {
            checkForConnected();

            if (primaryConnected && secondaryConnected)
            {
                PRINT_DEBUG_INFO("\tWaitForConnectedWlanInterfaces - primary and secondary interfaces are connected\n");
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

std::optional<int> GetSecondaryInterfaceBestEffort(HANDLE wlanHandle)
{
    const auto profile = NetworkInformation::GetInternetConnectionProfile();
    if (!profile.IsWlanConnectionProfile())
    {
        return std::nullopt;
    }

    const auto internetInterfaceGuid = profile.NetworkAdapter().NetworkAdapterId();

    auto primaryInterfaces = GetPrimaryInterfaceGuids(wlanHandle);
    if (primaryInterfaces.empty())
    {
        FAIL_FAST_MSG("WLAN connection without a WLAN interface");
    }

    // This is a global setting, the interface GUID doesn't matter.
    EnableSecondaryInterface(wlanHandle, primaryInterfaces[0]);

    // Check the connected interface is a device interface
    const auto matchingWlanInterface = std::ranges::find(primaryInterfaces, *reinterpret_cast<const GUID*>(&internetInterfaceGuid));
    if (matchingWlanInterface == primaryInterfaces.end())
    {
        return std::nullopt;
    }

    // Query the secondary interface (if any)
    if (auto secondaryInterface = GetSecondaryInterfaceGuid(wlanHandle, *matchingWlanInterface))
    {
        WaitForConnectedWlanInterfaces(WlanInterfaceGuids{*reinterpret_cast<const GUID*>(&internetInterfaceGuid), *secondaryInterface});
        return ConvertInterfaceGuidToIndex(*secondaryInterface);
    }
    else
    {
        return std::nullopt;
    }
}

} // namespace multipath