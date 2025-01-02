// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdio>
#include <exception>
#include <string>
#include <windows.h>
#include "ctWmiInitialize.hpp"

PCWSTR PrintFwBooleanFlag(int32_t flag) noexcept
{
	switch (flag)
	{
	case 0:
		return L"False";
	case 1:
		return L"True";
	case 2:
		return L"Not Configured";
	default:
		return L"Unexpected value";
	}
}

PCWSTR PrintNetFwAction(int32_t flag) noexcept
{
    switch (flag)
    {
    case 0:
		return L"Not Configured (default)";
    case 2:
		return L"Allow";
    case 4:
		return L"Block";
    default:
		return L"Unexpected value";
    }
}

int __cdecl main()
try
{
	const auto co_init = wil::CoInitializeEx();

	ctl::ctWmiEnumerate firewall_profile_enumerator{ ctl::ctWmiService{L"ROOT\\StandardCimv2"} };
	for (const auto& profile : firewall_profile_enumerator.query(L"SELECT * FROM MSFT_NetFirewallProfile"))
	{
		std::wstring profile_name;
		bool property_exists = profile.get(L"Name", &profile_name);
		if (!property_exists)
		{
			// this should never happen: NetFirewallProfile::Name should always exist
			wprintf(L"*** something is wrong - the Name string property should exist in NetFirewallProfile\n");
			continue;
		}

		int32_t is_enabled{};
		property_exists = profile.get(L"Enabled", &is_enabled);
		if (!property_exists)
		{
			wprintf(L"*** something is wrong - the Enabled INT32 property should exist in NetFirewallProfile\n");
			continue;
		}

		int32_t default_inbound_action{};
		property_exists = profile.get(L"DefaultInboundAction", &default_inbound_action);
		if (!property_exists)
		{
			wprintf(L"*** something is wrong - the DefaultInboundAction INT32 property should exist in NetFirewallProfile\n");
			continue;
		}

		int32_t default_outbound_action{};
		property_exists = profile.get(L"DefaultOutboundAction", &default_outbound_action);
		if (!property_exists)
		{
			wprintf(L"*** something is wrong - the DefaultOutboundAction INT32 property should exist in NetFirewallProfile\n");
			continue;
		}

		int32_t local_rules_allowed{};
		property_exists = profile.get(L"AllowLocalFirewallRules", &local_rules_allowed);
		if (!property_exists)
		{
			wprintf(L"*** something is wrong - the AllowLocalFirewallRules INT32 property should exist in NetFirewallProfile\n");
			continue;
		}

		wprintf(
			L"Profile %ws\n"
			L"  Enabled : %ws\n"
			L"  Default Inbound Action: %ws\n"
			L"  Default Outbound Action: %ws\n"
			L"  Allow Local Firewall Rules: %ws\n",
			profile_name.c_str(),
			PrintFwBooleanFlag(is_enabled),
			PrintNetFwAction(default_inbound_action),
			PrintNetFwAction(default_outbound_action),
			PrintFwBooleanFlag(local_rules_allowed));
	}
}
catch (const std::exception& e)
{
	wprintf(L"Failure : %hs\n", e.what());
}