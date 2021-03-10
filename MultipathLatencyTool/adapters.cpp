#include "adapters.h"
#include "debug.h"

#include <winrt/Windows.Foundation.Collections.h>
#include <netioapi.h>

#include <wil/result.h>

using namespace winrt;
using namespace Windows::Networking::Connectivity;

namespace multipath {

wil::unique_wlan_handle OpenWlanHandle()
{
    constexpr DWORD clientVersion = 2; // Vista+ APIs
    DWORD curVersion = 0;
    wil::unique_wlan_handle wlanHandle;
    auto error = ::WlanOpenHandle(clientVersion, nullptr, &curVersion, &wlanHandle);
    FAIL_FAST_IF_WIN32_ERROR_MSG(error, "WlanOpenHandle failed");

    return wlanHandle;
}

std::vector<GUID> GetPrimaryInterfaceGuids(HANDLE wlanHandle)
{
    std::vector<GUID> primaryInterfaces{};

    wil::unique_wlan_ptr<WLAN_INTERFACE_INFO_LIST> primaryInterfaceList{};
    const auto error = WlanEnumInterfaces(wlanHandle, nullptr, wil::out_param(primaryInterfaceList));
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

void RequestSecondaryInterface(HANDLE wlanHandle)
{
    auto wlanInterfaceGuids = GetPrimaryInterfaceGuids(wlanHandle);

    BOOL enable = TRUE;
    const auto error = WlanSetInterface(
        wlanHandle, &wlanInterfaceGuids.front(), wlan_intf_opcode_secondary_sta_synchronized_connections, sizeof(BOOL), static_cast<PVOID>(&enable), nullptr);
    THROW_IF_WIN32_ERROR_MSG(error, "WlanSetInterface(wlan_intf_opcode_secondary_sta_synchronized_connections) failed");

    PRINT_DEBUG_INFO("\tSetSecondaryInterfaceEnabled - successfully set opcode "
                     "`wlan_intf_opcode_secondary_sta_synchronized_connections`\n");
}

std::optional<winrt::guid> GetSecondaryInterfaceGuid(HANDLE wlanHandle, const winrt::guid& primaryInterfaceGuid)
{
    const auto wlanInterfaces = GetPrimaryInterfaceGuids(wlanHandle);
    auto matchingWlanInterface = std::ranges::find_if(
        wlanInterfaces, [&](const auto& guid) { return guid == *reinterpret_cast<const GUID*>(&primaryInterfaceGuid); });

    // The IP interface guid doesn't match a wlan adapter guid: don't use dual sta
    if (matchingWlanInterface == wlanInterfaces.end())
    {
        return std::nullopt;
    }
    
    wil::unique_wlan_ptr<WLAN_INTERFACE_INFO_LIST> secondaryInterfaceList{};
    DWORD dataSize = 0;

    const auto error = WlanQueryInterface(
        wlanHandle,
        &*matchingWlanInterface,
        wlan_intf_opcode_secondary_sta_interfaces,
        nullptr,
        &dataSize,
        wil::out_param_ptr<PVOID*>(secondaryInterfaceList),
        nullptr);
    THROW_IF_WIN32_ERROR_MSG(error, "WlanQueryInterface failed");

    PRINT_DEBUG_INFO("\tGetSecondaryInterfaceGuids - received %lu secondary interface GUIDs\n", secondaryInterfaceList->dwNumberOfItems);

    // There is at most one secondary interface for a primary interface
    if (secondaryInterfaceList->dwNumberOfItems > 0)
    {
        return *reinterpret_cast<winrt::guid*>(&secondaryInterfaceList->InterfaceInfo[0].InterfaceGuid);
    }
    else
    {
        return std::nullopt;
    }
}



bool IsAdapterConnected(const winrt::guid& adapterId)
{
    const auto profiles = NetworkInformation::GetConnectionProfiles();
    for (const auto& profile : profiles)
    {
        const auto profileAdapterId = profile.NetworkAdapter().NetworkAdapterId();
        if (adapterId == profileAdapterId)
        {
            const auto connectivityLevel = profile.GetNetworkConnectivityLevel();
            PRINT_DEBUG_INFO("\tAdapter connectivity level: %d\n", connectivityLevel);

            return connectivityLevel == NetworkConnectivityLevel::InternetAccess;
        }
    }
    PRINT_DEBUG_INFO("\tAdapter not found\n");
    return false;
}

int ConvertInterfaceGuidToIndex(const winrt::guid& interfaceGuid)
{
    NET_LUID interfaceLuid{};
    auto error = ConvertInterfaceGuidToLuid(reinterpret_cast<const GUID*>(&interfaceGuid), &interfaceLuid);
    THROW_IF_NTSTATUS_FAILED_MSG(error, "ConvertInterfaceGuidToLuid failed");

    NET_IFINDEX interfaceIndex = 0;
    error = ConvertInterfaceLuidToIndex(&interfaceLuid, &interfaceIndex);
    THROW_IF_NTSTATUS_FAILED_MSG(error, "ConvertInterfaceLuidToIndex failed");

    return static_cast<int>(interfaceIndex);
}

} // namespace multipath