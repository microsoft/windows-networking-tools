// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <iostream>
#include <chrono>
#include <string>

#include <windows.h>
#include <Rpc.h>

#include <winrt/Windows.Networking.Connectivity.h>
#include <wil/resource.h>

using std::to_wstring;

inline std::wstring tabs_to_wstring(uint32_t count)
{
    std::wstring returnString;
    for (uint32_t space_count = 0; space_count < count; ++space_count)
    {
        returnString.append(L"    ");
    }
    return returnString;
}

inline std::wstring to_wstring(const FILETIME& fileTime)
{
    std::wstring returnString;
    if (fileTime.dwHighDateTime > 0ul || fileTime.dwLowDateTime > 0ul)
    {
        SYSTEMTIME systemTime{};
        if (FileTimeToSystemTime(&fileTime, &systemTime))
        {
            SYSTEMTIME localTime{};
            if (SystemTimeToTzSpecificLocalTime(nullptr, &systemTime, &localTime))
            {
                const size_t formattedStringLength = 64;
                WCHAR formattedString[formattedStringLength]{};
                if (GetDateFormatEx(LOCALE_NAME_INVARIANT, DATE_SHORTDATE, &localTime, nullptr, formattedString, formattedStringLength, nullptr) > 0)
                {
                    returnString.append(formattedString).append(L", ");
                }
                if (GetTimeFormatEx(LOCALE_NAME_INVARIANT, LOCALE_USE_CP_ACP | TIME_FORCE24HOURFORMAT, &localTime, nullptr, formattedString, formattedStringLength) > 0)
                {
                    returnString.append(formattedString);
                }
            }
        }
    }

    return returnString;
}

inline std::wstring to_wstring(const DateTime& dateTime)
{
    LARGE_INTEGER integerConversion{};
    integerConversion.QuadPart = dateTime.time_since_epoch().count();
    FILETIME ft{};
    ft.dwLowDateTime = integerConversion.LowPart;
    ft.dwHighDateTime = static_cast<LONG>(integerConversion.HighPart);
    return to_wstring(ft);
}

inline std::wstring to_wstring(const TimeSpan& timeSpan)
{
    return std::to_wstring(timeSpan.count() / 10000).append(L" ms.");
}


inline std::wstring to_wstring(bool b)
{
    return b ? L"true" : L"false";
}

inline std::wstring to_wstring(NetworkCostType cost)
{
    switch (cost)
    {
    case NetworkCostType::Unknown: return L"Unknown";
    case NetworkCostType::Unrestricted: return L"Unrestricted";
    case NetworkCostType::Fixed: return L"Fixed";
    case NetworkCostType::Variable: return L"Variable";
    }
    return std::wstring(L"<Unknown NetworkCost ").append(std::to_wstring(static_cast<uint32_t>(cost))).append(L">\n");
}

inline std::wstring to_wstring(NetworkConnectivityLevel level)
{
    switch (level)
    {
    case NetworkConnectivityLevel::None: return L"None";
    case NetworkConnectivityLevel::LocalAccess: return L"LocalAccess";
    case NetworkConnectivityLevel::ConstrainedInternetAccess: return L"ConstrainedInternetAccess";
    case NetworkConnectivityLevel::InternetAccess: return L"InternetAccess";
    }
    return std::wstring(L"<Unknown NetworkConnectivityLevel ").append(std::to_wstring(static_cast<uint32_t>(level))).append(L">\n");
}

inline std::wstring to_wstring(DomainConnectivityLevel level)
{
    switch (level)
    {
    case DomainConnectivityLevel::None: return L"None";
    case DomainConnectivityLevel::Unauthenticated: return L"Unauthenticated";
    case DomainConnectivityLevel::Authenticated: return L"Authenticated";
    }
    return std::wstring(L"<Unknown DomainConnectivityLevel ").append(std::to_wstring(static_cast<uint32_t>(level))).append(L">\n");
}

inline std::wstring to_wstring(NetworkAuthenticationType type)
{
    switch (type)
    {
    case NetworkAuthenticationType::None: return L"None";
    case NetworkAuthenticationType::Unknown: return L"Unknown";
    case NetworkAuthenticationType::Open80211: return L"Open80211";
    case NetworkAuthenticationType::SharedKey80211: return L"SharedKey80211";
    case NetworkAuthenticationType::Wpa: return L"Wpa";
    case NetworkAuthenticationType::WpaPsk: return L"WpaPsk";
    case NetworkAuthenticationType::WpaNone: return L"WpaNone";
    case NetworkAuthenticationType::Rsna: return L"Rsna";
    case NetworkAuthenticationType::RsnaPsk: return L"RsnaPsk";
    case NetworkAuthenticationType::Ihv: return L"Ihv";
    case NetworkAuthenticationType::Wpa3: return L"Wpa3";
    case NetworkAuthenticationType::Wpa3Sae: return L"Wpa3Sae";
    }
    return std::wstring(L"<Unknown NetworkAuthenticationType ").append(std::to_wstring(static_cast<uint32_t>(type))).append(L">\n");
}

inline std::wstring to_wstring(NetworkEncryptionType type)
{
    switch (type)
    {
    case NetworkEncryptionType::None: return L"None";
    case NetworkEncryptionType::Unknown: return L"Unknown";
    case NetworkEncryptionType::Wep: return L"Wep";
    case NetworkEncryptionType::Wep40: return L"Wep40";
    case NetworkEncryptionType::Wep104: return L"Wep104";
    case NetworkEncryptionType::Tkip: return L"Tkip";
    case NetworkEncryptionType::Ccmp: return L"Ccmp";
    case NetworkEncryptionType::WpaUseGroup: return L"WpaUseGroup";
    case NetworkEncryptionType::RsnUseGroup: return L"RsnUseGroup";
    case NetworkEncryptionType::Ihv: return L"Ihv";
    }
    return std::wstring(L"<Unknown NetworkEncryptionType ").append(std::to_wstring(static_cast<uint32_t>(type))).append(L">\n");
}

inline std::wstring to_wstring(WwanNetworkIPKind kind)
{
    switch (kind)
    {
        case WwanNetworkIPKind::None: return L"None";
        case WwanNetworkIPKind::Ipv4: return L"Ipv4";
        case WwanNetworkIPKind::Ipv6: return L"Ipv6";
        case WwanNetworkIPKind::Ipv4v6: return L"Ipv4v6";
        case WwanNetworkIPKind::Ipv4v6v4Xlat: return L"Ipv4v6v4Xlat";
    }
    return std::wstring(L"<Unknown winrt::Windows::Networking::Connectivity::WwanNetworkIPKind ").append(std::to_wstring(static_cast<uint32_t>(kind))).append(L">\n");
}

inline std::wstring to_wstring(NetworkTypes type)
{
    if (type == NetworkTypes::None)
    {
        return L" None";
    }

    std::wstring returnString;
    if ((type & NetworkTypes::Internet) == NetworkTypes::Internet)
    {
        returnString.append(L" Internet");
    }
    if ((type & NetworkTypes::PrivateNetwork) == NetworkTypes::PrivateNetwork)
    {
        returnString.append(L" PrivateNetwork");
    }
    if (returnString.empty())
    {
        return std::wstring(L"<unknown NetworkTypes ").append(std::to_wstring(static_cast<uint32_t>(type))).append(L">\n");
    }
    return returnString;
}

inline std::wstring to_wstring(const WwanDataClass& dataClass)
{
    if (dataClass == WwanDataClass::None)
    {
        return L" None";
    }

    std::wstring returnString;
    if ((dataClass & WwanDataClass::Gprs) == WwanDataClass::Gprs)
    {
        returnString.append(L" Gprs");
    }
    if ((dataClass & WwanDataClass::Edge) == WwanDataClass::Edge)
    {
        returnString.append(L" Edge");
    }
    if ((dataClass & WwanDataClass::Umts) == WwanDataClass::Umts)
    {
        returnString.append(L" Umts");
    }
    if ((dataClass & WwanDataClass::Hsdpa) == WwanDataClass::Hsdpa)
    {
        returnString.append(L" Hsdpa");
    }
    if ((dataClass & WwanDataClass::Hsupa) == WwanDataClass::Hsupa)
    {
        returnString.append(L" Hsupa");
    }
    if ((dataClass & WwanDataClass::LteAdvanced) == WwanDataClass::LteAdvanced)
    {
        returnString.append(L" LteAdvanced");
    }
    if ((dataClass & WwanDataClass::Cdma1xRtt) == WwanDataClass::Cdma1xRtt)
    {
        returnString.append(L" Cdma1xRtt");
    }
    if ((dataClass & WwanDataClass::Cdma1xEvdo) == WwanDataClass::Cdma1xEvdo)
    {
        returnString.append(L" Cdma1xEvdo");
    }
    if ((dataClass & WwanDataClass::Cdma1xEvdoRevA) == WwanDataClass::Cdma1xEvdoRevA)
    {
        returnString.append(L" Cdma1xEvdoRevA");
    }
    if ((dataClass & WwanDataClass::Cdma1xEvdv) == WwanDataClass::Cdma1xEvdv)
    {
        returnString.append(L" Cdma1xEvdv");
    }
    if ((dataClass & WwanDataClass::Cdma3xRtt) == WwanDataClass::Cdma3xRtt)
    {
        returnString.append(L" Cdma3xRtt");
    }
    if ((dataClass & WwanDataClass::Cdma1xEvdoRevB) == WwanDataClass::Cdma1xEvdoRevB)
    {
        returnString.append(L" Cdma1xEvdoRevB");
    }
    if ((dataClass & WwanDataClass::CdmaUmb) == WwanDataClass::CdmaUmb)
    {
        returnString.append(L" CdmaUmb");
    }
    if ((dataClass & WwanDataClass::Custom) == WwanDataClass::Custom)
    {
        returnString.append(L" Custom");
    }
    if (returnString.empty())
    {
        return std::wstring(L"<unknown winrt::Windows::Networking::Connectivity::WwanDataClass ").append(std::to_wstring(static_cast<uint32_t>(dataClass))).append(L">\n");
    }
    return returnString;
}

inline std::wstring to_wstring(const WwanNetworkRegistrationState& state)
{
    switch (state)
    {
    case WwanNetworkRegistrationState::None: return L"None";
    case WwanNetworkRegistrationState::Deregistered: return L"Deregistered";
    case WwanNetworkRegistrationState::Searching: return L"Searching";
    case WwanNetworkRegistrationState::Home: return L"Home";
    case WwanNetworkRegistrationState::Roaming: return L"Roaming";
    case WwanNetworkRegistrationState::Partner: return L"Partner";
    case WwanNetworkRegistrationState::Denied: return L"Denied";
    }
    return std::wstring(L"<unknown winrt::Windows::Networking::Connectivity::WwanNetworkRegistrationState ").append(std::to_wstring(static_cast<uint32_t>(state))).append(L">\n");
}

inline std::wstring to_wstring(const LanIdentifierData& data, uint32_t tabs)
{
    if (!data)
    {
        return tabs_to_wstring(tabs) + L"<null>";
    }

    std::wstring returnString;
    returnString.append(tabs_to_wstring(tabs));
    returnString.append(L"Type: ").append(to_wstring(data.Type())).append(L"\n");
    returnString.append(tabs_to_wstring(tabs));
    returnString.append(L"Value: ");
    for (const auto& byte_value : data.Value())
    {
        wchar_t byteBuff[8]{};
        swprintf_s(byteBuff, L"0x%x", byte_value);
        returnString.append(byteBuff);
        returnString.append(L" ");
    }
    returnString.append(L"\n");
    return returnString;
}

inline std::wstring to_wstring(const guid& g)
{
    UUID uuid{};
    uuid.Data1 = g.Data1;
    uuid.Data2 = g.Data2;
    uuid.Data3 = g.Data3;
    uuid.Data4[0] = g.Data4[0];
    uuid.Data4[1] = g.Data4[1];
    uuid.Data4[2] = g.Data4[2];
    uuid.Data4[3] = g.Data4[3];
    uuid.Data4[4] = g.Data4[4];
    uuid.Data4[5] = g.Data4[5];
    uuid.Data4[6] = g.Data4[6];
    uuid.Data4[7] = g.Data4[7];

    wil::unique_rpc_wstr rpcString;
    const auto status = UuidToStringW(&uuid, &rpcString);
    if (status != RPC_S_OK)
    {
        return {};
    }

    return { reinterpret_cast<wchar_t*>(rpcString.get()) };
}

inline std::wstring to_wstring(const IReference<guid>& refGuid)
{
    const auto propertyValue = refGuid.try_as<IPropertyValue>();
    return  propertyValue ? to_wstring(propertyValue.GetGuid()) : L"<null>";
}

inline std::wstring to_wstring(const IReference<uint8_t>& refUint8)
{
    const auto propertyValue = refUint8.try_as<IPropertyValue>();
    return  propertyValue ? to_wstring(propertyValue.GetUInt8()) : L"<null>";
}

inline std::wstring to_wstring(const IReference<uint32_t>& refUint32)
{
    const auto propertyValue = refUint32.try_as<IPropertyValue>();
    return  propertyValue ? to_wstring(propertyValue.GetUInt32()) : L"<null>";
}

inline std::wstring to_wstring(const IReference<uint64_t>& refUint64)
{
    const auto propertyValue = refUint64.try_as<IPropertyValue>();
    return  propertyValue ? to_wstring(propertyValue.GetUInt64()) : L"<null>";
}

inline std::wstring to_wstring(const IReference<DateTime>& refDateTime)
{
    const auto propertyValue = refDateTime.try_as<IPropertyValue>();
    return  propertyValue ? to_wstring(propertyValue.GetDateTime()) : L"<null>";
}

inline std::wstring to_wstring(const NetworkAdapter& adapter, uint32_t tabs)
{
    std::wstring adapterString;
    adapterString.append(tabs_to_wstring(tabs));
    adapterString.append(L"OutboundMaxBitsPerSecond: ").append(std::to_wstring(adapter.OutboundMaxBitsPerSecond())).append(L"\n");
    adapterString.append(tabs_to_wstring(tabs));
    adapterString.append(L"InboundMaxBitsPerSecond: ").append(std::to_wstring(adapter.InboundMaxBitsPerSecond())).append(L"\n");
    adapterString.append(tabs_to_wstring(tabs));
    adapterString.append(L"IanaInterfaceType: ").append(std::to_wstring(adapter.IanaInterfaceType())).append(L"\n");
    adapterString.append(tabs_to_wstring(tabs));
    adapterString.append(L"NetworkAdapterId: ").append(to_wstring(adapter.NetworkAdapterId())).append(L"\n");
    const auto item = adapter.NetworkItem();
    adapterString.append(tabs_to_wstring(tabs));
    adapterString.append(L"NetworkItem\n");
    adapterString.append(tabs_to_wstring(tabs + 1));
    adapterString.append(L"NetworkTypes:").append(to_wstring(item.GetNetworkTypes())).append(L"\n");
    adapterString.append(tabs_to_wstring(tabs + 1));
    adapterString.append(L"NetworkId: ").append(to_wstring(item.NetworkId())).append(L"\n");
    return adapterString;
}

inline std::wstring to_wstring(const winrt::Windows::Networking::HostName& hostName)
{
    std::wstring hostNameString;
    hostNameString.append(tabs_to_wstring(1));
    hostNameString.append(L"HostName (ToString): ").append(hostName.ToString()).append(L"\n");
    hostNameString.append(tabs_to_wstring(1));
    hostNameString.append(L"DisplayName: ").append(hostName.DisplayName()).append(L"\n");
    hostNameString.append(tabs_to_wstring(1));
    hostNameString.append(L"CanonicalName: ").append(hostName.CanonicalName()).append(L"\n");
    hostNameString.append(tabs_to_wstring(1));
    hostNameString.append(L"RawName: ").append(hostName.RawName()).append(L"\n");
    hostNameString.append(tabs_to_wstring(1));
    hostNameString.append(L"IPInformation");
    const auto ipInformation = hostName.IPInformation();
    if (ipInformation)
    {
        hostNameString.append(L"\n");
        hostNameString.append(tabs_to_wstring(2));
        hostNameString.append(L"PrefixLength: ").append(to_wstring(ipInformation.PrefixLength())).append(L"\n");
        hostNameString.append(tabs_to_wstring(2));
        hostNameString.append(L"NetworkAdapter:\n");
        hostNameString.append(to_wstring(ipInformation.NetworkAdapter(), 2));
    }
    else
    {
        hostNameString.append(L": <null>\n");
    }
    return hostNameString;
}

inline std::wstring to_wstring(const LanIdentifier& identifier, uint32_t tabs)
{
    std::wstring identifierString;
    identifierString.append(tabs_to_wstring(tabs));
    identifierString.append(L"NetworkAdapterId: ").append(to_wstring(identifier.NetworkAdapterId())).append(L"\n");
    identifierString.append(tabs_to_wstring(tabs));
    identifierString.append(L"InfrastructureId\n");
    identifierString.append(to_wstring(identifier.InfrastructureId(), tabs + 1));
    identifierString.append(tabs_to_wstring(tabs));
    identifierString.append(L"PortId\n");
    identifierString.append(to_wstring(identifier.PortId(), tabs + 1));
    return identifierString;
}

inline std::wstring to_wstring(const ProxyConfiguration& config, uint32_t tabs)
{
    std::wstring proxyString;
    proxyString.append(tabs_to_wstring(tabs));
    proxyString.append(L"CanConnectDirectly: ").append(to_wstring(config.CanConnectDirectly())).append(L"\n");
    proxyString.append(tabs_to_wstring(tabs));
    proxyString.append(L"ProxyUris\n");
    unsigned count = 0;
    for (const auto& uri : config.ProxyUris())
    {
        ++count;
        proxyString.append(tabs_to_wstring(tabs + 1));
        proxyString.append(to_wstring(count)).append(L".  ------------------\n");
        proxyString.append(tabs_to_wstring(tabs + 1));
        proxyString.append(uri.ToString()).append(L"\n");
    }
    return proxyString;
}