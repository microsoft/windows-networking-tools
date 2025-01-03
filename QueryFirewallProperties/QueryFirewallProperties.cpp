// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdio>
#include <exception>
#include <string>
#include <windows.h>
#include "ctWmiInitialize.hpp"

#include <wil/com.h>
#include <wil/resource.h>

// MOF of MSFT_NetFirewallProfile
//
//  uint16 Enabled;
//	uint16 DefaultInboundAction;
//	uint16 DefaultOutboundAction;
//	uint16 AllowInboundRules;
//	uint16 AllowLocalFirewallRules;
//	uint16 AllowLocalIPsecRules;
//	uint16 AllowUserApps;
//	uint16 AllowUserPorts;
//	uint16 AllowUnicastResponseToMulticast;
//	uint16 NotifyOnListen;
//	string LogFileName;
//	uint64 LogMaxSizeKilobytes;
//	uint16 LogAllowed;
//	uint16 LogBlocked;
//	uint16 LogIgnored;
//	string DisabledInterfaceAliases[];
//	uint16 EnableStealthModeForIPsec;

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

int __cdecl wmain(int argc, wchar_t** argv)
try
{
	// by default write out the effective policy - from ActiveStore
	// allow for -PolicyStore (string)
	// ... following the Powershell command
	//
	// valid stores are:
	// ActiveStore
	// PersistentStore
	// RSOP

	const auto co_init = wil::CoInitializeEx();

	PCWSTR policyStoreValue = L"ActiveStore";
	if (argc == 3)
	{
		if (0 == lstrcmpiW(L"-PolicyStore", argv[1]))
		{
			policyStoreValue = argv[2];
		}
	}
	ctl::ctWmiEnumerate firewall_profile_enumerator{ ctl::ctWmiService{L"ROOT\\StandardCimv2"} };

	wprintf(L"Enumerating NetFirewallProfile from the policy store %ws\n", policyStoreValue);

	// PolicyStore is a context object to be passed to MSFT_NetFirewallProfile
	// analogous to the powershell command: Get-NetFirewallProfile -PolicyStore ActiveStore
	wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
	THROW_IF_FAILED(policyStoreContext->SetValue(
		L"PolicyStore",
		0,
		wil::make_variant_bstr(policyStoreValue).addressof()));

	bool instances_returned = false;
	for (const auto& profile : firewall_profile_enumerator.query(L"SELECT * FROM MSFT_NetFirewallProfile", policyStoreContext))
	{
		instances_returned = true;

		std::wstring profile_name;
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"Name", &profile_name));

		int32_t is_enabled{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"Enabled", &is_enabled));

		int32_t default_inbound_action{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"DefaultInboundAction", &default_inbound_action));

		int32_t default_outbound_action{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"DefaultOutboundAction", &default_outbound_action));

		int32_t inbound_rules_allowed{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"AllowInboundRules", &inbound_rules_allowed));

		int32_t local_rules_allowed{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"AllowLocalFirewallRules", &local_rules_allowed));

		int32_t local_ipsec_rules_allowed{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"AllowLocalIPsecRules", &local_rules_allowed));

		int32_t user_apps_allowed{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"AllowUserApps", &user_apps_allowed));

		int32_t user_ports_allowed{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"AllowUserPorts", &user_ports_allowed));

		int32_t unicast_response_to_multicast_allowed{};
		THROW_HR_IF(E_UNEXPECTED,
			!profile.get(L"AllowUnicastResponseToMulticast", &unicast_response_to_multicast_allowed));

		int32_t notify_on_listen{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"NotifyOnListen", &notify_on_listen));

		wil::unique_bstr log_file_name;
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"LogFileName", &log_file_name));

		uint64_t log_file_max_size{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"LogMaxSizeKilobytes", &log_file_max_size));

		int32_t log_allowed{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"LogAllowed", &log_allowed));

		int32_t log_blocked{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"LogBlocked", &log_blocked));

		int32_t log_ignored{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"LogIgnored", &log_ignored));

		int32_t enable_ipsec_stealth_mode{};
		THROW_HR_IF(E_UNEXPECTED, !profile.get(L"EnableStealthModeForIPsec", &enable_ipsec_stealth_mode));

		//	string DisabledInterfaceAliases[];

		wprintf(
			L"\nProfile %ws\n"
			L"  Enabled : %ws\n"
			L"  Default Inbound Action: %ws\n"
			L"  Default Outbound Action: %ws\n"
			L"  Allow Inbound Rules: %ws\n"
			L"  Allow Local Firewall Rules: %ws\n"
			L"  Allow Local IPsec Rules: %ws\n"
			L"  Allow User Apps: %ws\n"
			L"  Allow User Ports: %ws\n"
			L"  Allow Unicast Response To Multicast: %ws\n"
			L"  Notify On Listen: %ws\n"
			L"  Log File Name: %ws\n"
			L"  Log File Max Size (KB): %llu\n"
			L"  Log Allowed: %ws\n"
			L"  Log Blocked: %ws\n"
			L"  Log Ignored: %ws\n"
			L"  Enable Stealth Mode For IPsec: %ws\n",
			profile_name.c_str(),
			PrintFwBooleanFlag(is_enabled),
			PrintNetFwAction(default_inbound_action),
			PrintNetFwAction(default_outbound_action),
			PrintFwBooleanFlag(inbound_rules_allowed),
			PrintFwBooleanFlag(local_rules_allowed),
			PrintFwBooleanFlag(local_ipsec_rules_allowed),
			PrintFwBooleanFlag(user_apps_allowed),
			PrintFwBooleanFlag(user_ports_allowed),
			PrintFwBooleanFlag(unicast_response_to_multicast_allowed),
			PrintFwBooleanFlag(notify_on_listen),
			log_file_name.get(),
			log_file_max_size,
			PrintFwBooleanFlag(log_allowed),
			PrintFwBooleanFlag(log_blocked),
			PrintFwBooleanFlag(log_ignored),
			PrintFwBooleanFlag(enable_ipsec_stealth_mode)
		);
	}

	if (!instances_returned)
	{
	    wprintf(L"\n** No policy objects returned for the specified policy store **\n");
	}
}
catch (const std::exception& e)
{
	wprintf(L"Failure : %hs\n", e.what());
}
