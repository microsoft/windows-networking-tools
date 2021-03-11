#pragma once

#include <Windows.h>
#include <wlanapi.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <wil/resource.h>
#include <optional>

namespace multipath {
wil::unique_wlan_handle OpenWlanHandle();
void RequestSecondaryInterface(HANDLE wlanHandle);
winrt::guid GetPrimaryInterfaceGuid() noexcept;
std::optional<winrt::guid> GetSecondaryInterfaceGuid(HANDLE wlanHandle, const winrt::guid& primaryInterfaceGuid);
int ConvertInterfaceGuidToIndex(const winrt::guid& interfaceGuid);
bool IsAdapterConnected(const winrt::guid& adapterId);
}