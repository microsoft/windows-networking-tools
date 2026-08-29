#pragma once
#include <string>
#include <winsock2.h>
#include <ws2ipdef.h>

std::string IfTypeToString(ULONG ifType);
std::string IfTunnelTypeToString(ULONG tunnelType);

void LoadIpProperties() noexcept;
std::wstring PrintIPInterfaceInfo(int space_count, const in_addr& local_addr) noexcept;
std::wstring PrintIPInterfaceInfo(int space_count, const in6_addr& local_addr) noexcept;