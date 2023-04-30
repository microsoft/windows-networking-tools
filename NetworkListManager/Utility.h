// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <array>
#include <cstdio>
#include <string>
#include <vector>
#include <OaIdl.h>   // for VARIANT
#include <OleAuto.h> // for VariantTimeToSystemTime
#include <OCIdl.h>   // for IConnectionPointContainer, IConnectionPoint
#include <WinSock2.h>
#include <windows.h>
#include <wrl.h>
#include <wil/resource.h>
#include <wil/result.h>
#include <wil/result_macros.h>
#include <netlistmgr.h>

namespace Utility
{
    constexpr size_t c_maximumInstanceWidth{66};
    constexpr char c_instanceCharacter{L'-'};
    const std::wstring c_instanceFooter(c_maximumInstanceWidth, c_instanceCharacter);
    inline std::wstring PrintInstanceHeader(_In_ PCWSTR pHeader)
    {
        const auto len = wcslen(pHeader);
        FAIL_FAST_IF(len > c_maximumInstanceWidth);
        const auto headerLength = static_cast<std::wstring::size_type>((c_maximumInstanceWidth - len) / 2);
        std::wstring formattedString(headerLength * 2, c_instanceCharacter);
        formattedString.insert(headerLength, pHeader);
        if ((c_maximumInstanceWidth - len) % 2 == 1)
        {
            formattedString.push_back(c_instanceCharacter);
        }
        // always inserting a line after the header
        formattedString.push_back(L'\n');
        return formattedString;
    }

    inline std::wstring PrintInstanceFooter()
    {
        return c_instanceFooter + L"\n";
    }

    inline PCWSTR ToString(const NLM_NETWORK_CATEGORY& nlmNetworkCategory)
    {
        switch (nlmNetworkCategory)
        {
        case NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED:
            return L" DomainAuthenticated";
        case NLM_NETWORK_CATEGORY_PRIVATE:
            return L" Private";
        case NLM_NETWORK_CATEGORY_PUBLIC:
            return L" Public";
        }
        return std::to_wstring(static_cast<int32_t>(nlmNetworkCategory)).c_str();
    }

    inline std::wstring ToString(const NLM_CONNECTIVITY& nlmConnectivity)
    {
        // first check if zero
        if (nlmConnectivity == NLM_CONNECTIVITY_DISCONNECTED)
        {
            return L" Disconnected";
        }

        std::wstring returnString;
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV4_INTERNET)
        {
            returnString.append(L" IPv4-Internet");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV4_LOCALNETWORK)
        {
            returnString.append(L" IPv4-Local");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV4_NOTRAFFIC)
        {
            returnString.append(L" IPv4-NoTraffic");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV4_SUBNET)
        {
            returnString.append(L" IPv4-Subnet");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV6_INTERNET)
        {
            returnString.append(L" IPv6-Internet");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV6_LOCALNETWORK)
        {
            returnString.append(L" IPv6-Local");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV6_NOTRAFFIC)
        {
            returnString.append(L" IPv6-NoTraffic");
        }
        if (nlmConnectivity & NLM_CONNECTIVITY_IPV6_SUBNET)
        {
            returnString.append(L" IPv6-Subnet");
        }

        if (returnString.empty())
        {
            returnString.assign(std::to_wstring(static_cast<int32_t>(nlmConnectivity)));
        }

        return returnString;
    }

    inline PCWSTR ToString(const NLM_DOMAIN_TYPE& nlmDomainType) noexcept
    {
        switch (nlmDomainType)
        {
        case NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED:
            return L" DomainAuthenticated";
        case NLM_DOMAIN_TYPE_DOMAIN_NETWORK:
            return L" DomainNetwork";
        case NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK:
            return L" NonDomainNetwork";
        }
        return std::to_wstring(static_cast<int32_t>(nlmDomainType)).c_str();
    }

    inline std::wstring ToString(const NLM_NETWORK_CLASS& networkClass)
    {
        switch (networkClass)
        {
        case NLM_NETWORK_IDENTIFIED:
            return L"Identified";
        case NLM_NETWORK_IDENTIFYING:
            return L"Identifying";
        case NLM_NETWORK_UNIDENTIFIED:
            return L"Unidentified";
        }

        return std::to_wstring(static_cast<int32_t>(networkClass));
    }

    inline std::wstring ToString(const NLM_CONNECTION_COST& cost)
    {
        // first check if zero
        if (cost == NLM_CONNECTION_COST_UNKNOWN)
        {
            return L" Unknown";
        }

        std::wstring returnString;
        if (cost & NLM_CONNECTION_COST_APPROACHINGDATALIMIT)
        {
            returnString.append(L" ApproachingDataLimit");
        }
        if (cost & NLM_CONNECTION_COST_CONGESTED)
        {
            returnString.append(L" Congested");
        }
        if (cost & NLM_CONNECTION_COST_FIXED)
        {
            returnString.append(L" Fixed");
        }
        if (cost & NLM_CONNECTION_COST_OVERDATALIMIT)
        {
            returnString.append(L" OverDataLimit");
        }
        if (cost & NLM_CONNECTION_COST_ROAMING)
        {
            returnString.append(L" Roaming");
        }
        if (cost & NLM_CONNECTION_COST_UNRESTRICTED)
        {
            returnString.append(L" Unrestricted");
        }
        if (cost & NLM_CONNECTION_COST_VARIABLE)
        {
            returnString.append(L" Variable");
        }

        if (returnString.empty())
        {
            returnString.assign(std::to_wstring(static_cast<int32_t>(cost)));
        }

        return returnString;
    }

    inline std::wstring ToString(const NLM_NETWORK_PROPERTY_CHANGE& nlmNetworkProperty)
    {
        std::wstring returnString;

        if (nlmNetworkProperty & NLM_NETWORK_PROPERTY_CHANGE_CATEGORY_VALUE)
        {
            returnString.append(L" CategoryValue");
        }
        if (nlmNetworkProperty & NLM_NETWORK_PROPERTY_CHANGE_CONNECTION)
        {
            returnString.append(L" Connection");
        }
        if (nlmNetworkProperty & NLM_NETWORK_PROPERTY_CHANGE_DESCRIPTION)
        {
            returnString.append(L" Description");
        }
        if (nlmNetworkProperty & NLM_NETWORK_PROPERTY_CHANGE_ICON)
        {
            returnString.append(L" Icon");
        }
        if (nlmNetworkProperty & NLM_NETWORK_PROPERTY_CHANGE_NAME)
        {
            returnString.append(L" Name");
        }

        if (returnString.empty())
        {
            returnString.assign(std::to_wstring(static_cast<int32_t>(nlmNetworkProperty)));
        }

        return returnString;
    }

    inline PCWSTR ToString(const NLM_CONNECTION_PROPERTY_CHANGE& nlmConnectionProperty) noexcept
    {
        if (nlmConnectionProperty == NLM_CONNECTION_PROPERTY_CHANGE_AUTHENTICATION)
        {
            return L"The Authentication (Domain Type) of this Network Connection has changed";
        }

        return std::to_wstring(static_cast<int32_t>(nlmConnectionProperty)).c_str();
    }

    inline std::wstring ToString(const NLM_INTERNET_CONNECTIVITY& connectivity)
    {
        std::wstring returnString;
        if (connectivity & NLM_INTERNET_CONNECTIVITY_CORPORATE)
        {
            returnString.append(L" Corporate");
        }
        if (connectivity & NLM_INTERNET_CONNECTIVITY_PROXIED)
        {
            returnString.append(L" Proxied");
        }
        if (connectivity & NLM_INTERNET_CONNECTIVITY_WEBHIJACK)
        {
            returnString.append(L"WebHijack");
        }

        return returnString.empty() ? std::to_wstring(static_cast<int32_t>(connectivity)) : returnString;
    }

    inline std::wstring ToString(_In_ VARIANT* variant)
    {
        switch (variant->vt)
        {
        case VT_EMPTY:
            return L"<empty>";
        case VT_NULL:
            return L"<null>";
        case VT_BOOL:
            return (variant->boolVal ? L"true" : L"false");
        default:
            return L"<unknown variant type>"; 
        }
    }

    inline std::wstring ToString(NLM_ENUM_NETWORK networkEnum)
    {
        switch (networkEnum)
        {
        case NLM_ENUM_NETWORK_CONNECTED:
            return L"NLM_ENUM_NETWORK_CONNECTED";
        case NLM_ENUM_NETWORK_DISCONNECTED:
            return L"NLM_ENUM_NETWORK_DISCONNECTED";
        case NLM_ENUM_NETWORK_ALL:
            return L"NLM_ENUM_NETWORK_ALL";
        default:
            return std::to_wstring(static_cast<int32_t>(networkEnum));
        }
    }
}
