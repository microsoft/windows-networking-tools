// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>

#include <Windows.h>
#include "firewall.h"
#include <netfw.h>
#include <sddl.h>

#include "WfpCounters.h"
#include "FwDiagnose.h"

#include <wil/resource.h>

static
std::wstring
ToHex(uint32_t value)
{
	WCHAR string_value[16]{};
	swprintf_s(string_value, L"0x%X", value);
	return std::wstring{ string_value };
}

static
std::wstring
ToString(FW_DIRECTION direction)
{
	switch (direction)
	{
	case FW_DIR_INVALID: return L"FW_DIR_INVALID";
	case FW_DIR_IN: return L"FW_DIR_IN";
	case FW_DIR_OUT: return L"FW_DIR_OUT";
	default:
		return L"(unknown FW_DIRECTION " + std::to_wstring(direction) + L")";
	}
}

static
std::wstring
ToString(NET_FW_IP_PROTOCOL protocol)
{
	switch (protocol)
	{
	case NET_FW_IP_PROTOCOL_TCP: return L"NET_FW_IP_PROTOCOL_TCP";
	case NET_FW_IP_PROTOCOL_UDP: return L"NET_FW_IP_PROTOCOL_UDP";
	case NET_FW_IP_PROTOCOL_ANY: return L"NET_FW_IP_PROTOCOL_ANY";
	default:
		return std::to_wstring(protocol);
	}
}

static
std::wstring
ToString(FW_RULE_ACTION action)
{
	switch (action)
	{
	case FW_RULE_ACTION_INVALID: return L"FW_RULE_ACTION_INVALID";
	case FW_RULE_ACTION_ALLOW_BYPASS: return L"FW_RULE_ACTION_ALLOW_BYPASS";
	case FW_RULE_ACTION_BLOCK: return L"FW_RULE_ACTION_BLOCK";
	case FW_RULE_ACTION_ALLOW: return L"FW_RULE_ACTION_ALLOW";
	default:
		return L"(unknown FW_RULE_ACTION " + std::to_wstring(action) + L")";
	}
}

static
std::wstring
ToString(FW_OS_PLATFORM platform)
{
	std::wstring result;

	result += L"Platform: ";
	if (platform.bPlatform == VER_PLATFORM_WIN32s)
	{
		result += L"VER_PLATFORM_WIN32s";
	}
	else if (platform.bPlatform == VER_PLATFORM_WIN32_WINDOWS)
	{
		result += L"VER_PLATFORM_WIN32_WINDOWS";
	}
	else if (platform.bPlatform == VER_PLATFORM_WIN32_NT)
	{
		result += L"VER_PLATFORM_WIN32_NT";
	}
	else
	{
		result += L"(unknown platform " + std::to_wstring(platform.bPlatform) + L")";
	}

	result += L", Major Version: " + std::to_wstring(platform.bMajorVersion);
	result += L", Minor Version: " + std::to_wstring(platform.bMinorVersion);
	return result;
}

static
std::wstring
ToString(FW_RULE_ORIGIN_TYPE type)
{
	switch (type)
	{
	case FW_RULE_ORIGIN_INVALID: return L"FW_RULE_ORIGIN_INVALID";
	case FW_RULE_ORIGIN_LOCAL: return L"FW_RULE_ORIGIN_LOCAL";
	case FW_RULE_ORIGIN_GP: return L"FW_RULE_ORIGIN_GP";
	case FW_RULE_ORIGIN_DYNAMIC: return L"FW_RULE_ORIGIN_DYNAMIC";
	case FW_RULE_ORIGIN_AUTOGEN: return L"FW_RULE_ORIGIN_AUTOGEN";
	case FW_RULE_ORIGIN_HARDCODED: return L"FW_RULE_ORIGIN_HARDCODED";
	case FW_RULE_ORIGIN_MDM: return L"FW_RULE_ORIGIN_MDM";
		// Hyper-V rule origins for host translated rules
	case FW_RULE_ORIGIN_HOST_LOCAL: return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_LOCAL)";
	case FW_RULE_ORIGIN_HOST_GP: return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_GP)";
	case FW_RULE_ORIGIN_HOST_DYNAMIC: return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_DYNAMIC)";
	case FW_RULE_ORIGIN_HOST_MDM: return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_MDM)";
	default:
		return L"(unknown FW_RULE_ORIGIN_TYPE " + std::to_wstring(type) + L")";
	}
}

static
std::wstring
ToString(FW_RULE_FLAG flag)
{
	if (flag == FW_RULE_FLAGS_NONE)
	{
		return L"FW_RULE_FLAGS_NONE";
	}

	std::wstring result;
	if (flag & FW_RULE_FLAGS_ACTIVE)
	{
		result += L"FW_RULE_FLAGS_ACTIVE | ";
	}
	if (flag & FW_RULE_FLAGS_AUTHENTICATE)
	{
		result += L"FW_RULE_FLAGS_AUTHENTICATE | ";
	}
	if (flag & FW_RULE_FLAGS_AUTHENTICATE_WITH_ENCRYPTION)
	{
		result += L"FW_RULE_FLAGS_AUTHENTICATE_WITH_ENCRYPTION | ";
	}
	if (flag & FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE)
	{
		result += L"FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE | ";
	}
	if (flag & FW_RULE_FLAGS_LOOSE_SOURCE_MAPPED)
	{
		result += L"FW_RULE_FLAGS_LOOSE_SOURCE_MAPPED | ";
	}
	static_assert(FW_RULE_FLAGS_AUTOGENERATE_CONNECTION_SECURITY_RULE == FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION);
	if (flag & FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION)
	{
		result += L"FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION + FW_RULE_FLAGS_AUTOGENERATE_CONNECTION_SECURITY_RULE | ";
	}
	if (flag & FW_RULE_FLAGS_AUTH_WITH_ENC_NEGOTIATE)
	{
		result += L"FW_RULE_FLAGS_AUTH_WITH_ENC_NEGOTIATE | ";
	}
	if (flag & FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_APP)
	{
		result += L"FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_APP | ";
	}
	if (flag & FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_USER)
	{
		result += L"FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_USER | ";
	}
	if (flag & FW_RULE_FLAGS_AUTHENTICATE_BYPASS_OUTBOUND)
	{
		result += L"FW_RULE_FLAGS_AUTHENTICATE_BYPASS_OUTBOUND | ";
	}
	if (flag & FW_RULE_FLAGS_ALLOW_PROFILE_CROSSING)
	{
		result += L"FW_RULE_FLAGS_ALLOW_PROFILE_CROSSING | ";
	}
	if (flag & FW_RULE_FLAGS_LOCAL_ONLY_MAPPED)
	{
		result += L"FW_RULE_FLAGS_LOCAL_ONLY_MAPPED | ";
	}
	if (flag & FW_RULE_FLAGS_LUA_CONDITIONAL_ACE)
	{
		result += L"FW_RULE_FLAGS_LUA_CONDITIONAL_ACE | ";
	}
	if (flag & FW_RULE_FLAGS_BIND_TO_INTERFACE)
	{
		result += L"FW_RULE_FLAGS_BIND_TO_INTERFACE | ";
	}

	if (!result.empty())
	{
		// remove trailing " | "
		result.erase(result.size() - 3);
	}
	return result;
}

static
std::wstring
ToString(FW_RULE_FLAGS2 flag)
{
	if (flag == FW_RULE_FLAGS2_NONE)
	{
		return L"FW_RULE_FLAGS2_NONE";
	}

	std::wstring result;

	if (flag & FW_RULE_FLAGS2_SYSTEMOS_ONLY)
	{
		result += L"FW_RULE_FLAGS2_SYSTEMOS_ONLY | ";
	}
	if (flag & FW_RULE_FLAGS2_GAMEOS_ONLY)
	{
		result += L"FW_RULE_FLAGS2_GAMEOS_ONLY | ";
	}
	if (flag & FW_RULE_FLAGS2_DEVMODE)
	{
		result += L"FW_RULE_FLAGS2_DEVMODE | ";
	}
	if (flag & FW_RULE_FLAGS2_EMPTY_REMOTENAME)
	{
		result += L"FW_RULE_FLAGS2_EMPTY_REMOTENAME | ";
	}
	if (flag & FW_RULE_FLAGS2_NOT_REMOTENAME)
	{
		result += L"FW_RULE_FLAGS2_NOT_REMOTENAME | ";
	}
	if (flag & FW_RULE_FLAGS2_CALLOUT_AND_AUDIT)
	{
		result += L"FW_RULE_FLAGS2_CALLOUT_AND_AUDIT | ";
	}
	if (flag & FW_RULE_FLAGS2_APP_LOOPBACK)
	{
		result += L"FW_RULE_FLAGS2_APP_LOOPBACK | ";
	}
	if (flag & FW_RULE_FLAGS2_INDIRECT_NAME_RESOLVED)
	{
		result += L"FW_RULE_FLAGS2_INDIRECT_NAME_RESOLVED | ";
	}
	if (flag & FW_RULE_FLAGS2_INDIRECT_DESCRIPTION_RESOLVED)
	{
		result += L"FW_RULE_FLAGS2_INDIRECT_DESCRIPTION_RESOLVED | ";
	}
	if (flag & FW_RULE_FLAGS2_DELAY_ENFORCE)
	{
		result += L"FW_RULE_FLAGS2_DELAY_ENFORCE | ";
	}
	if (flag & FW_RULE_FLAGS2_AVOID_NETID)
	{
		result += L"FW_RULE_FLAGS2_AVOID_NETID | ";
	}
	if (flag & FW_RULE_FLAGS2_LOOPBACK)
	{
		result += L"FW_RULE_FLAGS2_LOOPBACK | ";
	}
	if (flag & FW_RULE_FLAGS2_EDP)
	{
		result += L"FW_RULE_FLAGS2_EDP | ";
	}
	if (flag & FW_RULE_FLAGS2_TENANT_RESTRICTIONS_HIGH_WEIGHT)
	{
		result += L"FW_RULE_FLAGS2_TENANT_RESTRICTIONS_HIGH_WEIGHT | ";
	}

	if (!result.empty())
	{
		// remove trailing " | "
		result.erase(result.size() - 3);
	}
	return result;
}


struct NormalizedFirewallRule
{
	FW_RULE* fwRule{};
	std::wstring ruleId;
	NormalizedString ruleName;
	std::wstring ruleDescription;

	NormalizedString normalizedRuleDetails;

	std::optional<bool> targetApplicationExists{ std::nullopt };

	std::wstring localUserOwnerName;
	std::wstring localUserDomainName;
	std::optional<bool> userNameResolvedSuccessfully{ std::nullopt };

	std::optional<bool> userNameResolvedSuccessfullyWithLocalProfile{ std::nullopt };

	size_t filter_count{ 0 };
	size_t filter_condition_count{ 0 };
	size_t duplicate_rule_count{ 0 };

	bool ruleEnabled = false;
	bool ruleDeleted = false;

	NormalizedFirewallRule(const NormalizedFirewallRule&) = delete;
	NormalizedFirewallRule& operator=(const NormalizedFirewallRule&) = delete;

	NormalizedFirewallRule(NormalizedFirewallRule&&) noexcept = default;
	NormalizedFirewallRule& operator=(NormalizedFirewallRule&&) noexcept = default;

	NormalizedFirewallRule() = default;
	~NormalizedFirewallRule() = default;

	static NormalizedFirewallRule BuildFromFWRule(FW_RULE* fwRule)
	{
		NormalizedFirewallRule normalizedRule;
		normalizedRule.fwRule = fwRule;

		if (fwRule->wszName)
		{
			std::wstring ruleName(fwRule->wszName);
			ProcessForStringResource(ruleName);
			normalizedRule.ruleName = NormalizedString::Normalize(ruleName);
		}

		if (fwRule->wszDescription)
		{
			normalizedRule.ruleDescription.assign(fwRule->wszDescription);
			ProcessForStringResource(normalizedRule.ruleDescription);
		}
		if (fwRule->wszRuleId)
		{
			normalizedRule.ruleId.assign(fwRule->wszRuleId);
		}

		normalizedRule.AppendValue(fwRule->wSchemaVersion);
		normalizedRule.AppendValue(fwRule->dwProfiles);
		normalizedRule.AppendValue(fwRule->Direction);
		normalizedRule.AppendValue(fwRule->wIpProtocol);
		// unnamed union for ports and ICMP types based on the IP Protocol
		switch (fwRule->wIpProtocol)
		{
		case 6:
		case 17:
		{
			// read TCP and UDP ports
			normalizedRule.AppendValue(fwRule->LocalPorts.wPortKeywords);
			normalizedRule.AppendValue(fwRule->LocalPorts.Ports);
			normalizedRule.AppendValue(fwRule->RemotePorts.wPortKeywords);
			normalizedRule.AppendValue(fwRule->RemotePorts.Ports);
			break;
		}

		case 1:
		case 58:
		{
			// read ICMP fields
			normalizedRule.AppendValue(fwRule->V4TypeCodeList);
			normalizedRule.AppendValue(fwRule->V6TypeCodeList);
			break;
		}

		// we don't have any other protocol-specific firewall rule properties
		default:
			break;
		}

		normalizedRule.AppendValue(fwRule->LocalAddresses.dwV4AddressKeywords);
		normalizedRule.AppendValue(fwRule->LocalAddresses.dwV6AddressKeywords);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V4SubNets);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V4Ranges);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V6SubNets);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V6Ranges);

		normalizedRule.AppendValue(fwRule->RemoteAddresses.dwV4AddressKeywords);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.dwV6AddressKeywords);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V4SubNets);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V4Ranges);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V6SubNets);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V6Ranges);

		normalizedRule.AppendValue(fwRule->LocalInterfaceIds);
		normalizedRule.AppendValue(fwRule->dwLocalInterfaceTypes);
		normalizedRule.AppendValue(fwRule->wszLocalApplication);
		normalizedRule.CheckIfFileExists();
		normalizedRule.AppendValue(fwRule->wszLocalService);

		normalizedRule.AppendValue(fwRule->Action);
		normalizedRule.AppendValue(fwRule->wFlags);
		normalizedRule.ruleEnabled = (fwRule->wFlags & FW_RULE_FLAGS_ACTIVE) == FW_RULE_FLAGS_ACTIVE;

		normalizedRule.AppendValue(fwRule->wszRemoteMachineAuthorizationList);
		normalizedRule.AppendValue(fwRule->wszRemoteUserAuthorizationList);
		normalizedRule.AppendValue(fwRule->wszEmbeddedContext);
		normalizedRule.AppendValue(fwRule->PlatformValidityList);

		normalizedRule.AppendValue(fwRule->Status);
		normalizedRule.AppendValue(fwRule->Origin);
		normalizedRule.AppendValue(fwRule->wszGPOName);
		normalizedRule.AppendValue(fwRule->Reserved);

		normalizedRule.AppendValue(fwRule->pMetaData);

		normalizedRule.AppendValue(fwRule->wszLocalUserAuthorizationList);
		normalizedRule.AppendValue(fwRule->wszPackageId);
		normalizedRule.AppendValue(fwRule->wszLocalUserOwner);
		normalizedRule.ProcessLocalUserSid();

		normalizedRule.AppendValue(fwRule->dwTrustTupleKeywords);
		normalizedRule.AppendValue(fwRule->OnNetworkNames);
		normalizedRule.AppendValue(fwRule->wszSecurityRealmId);
		normalizedRule.AppendValue(fwRule->wFlags2);
		normalizedRule.AppendValue(fwRule->RemoteOutServerNames);
		normalizedRule.AppendValue(fwRule->wszFqbn);
		normalizedRule.AppendValue(fwRule->compartmentId);
		return normalizedRule;
	}

	static std::wstring PrintRule(FW_RULE* fwRule)
	{
		if (!fwRule)
		{
			return L"<NULL>\n";
		}

		std::wstring result;

		result += L"Rule Name: ";
		result += !fwRule->wszName ? L"(null)" : fwRule->wszName;
		result += L"\n";

		result += L"Rule ID: ";
		result += !fwRule->wszRuleId ? L"(null)" : fwRule->wszRuleId;
		result += L"\n";

		result += L"Description: ";
		result += !fwRule->wszDescription ? L"(null)" : fwRule->wszDescription;
		result += L"\n";

		result += L"Schema Version: " + ToHex(fwRule->wSchemaVersion) + L"\n";
		result += L"Profiles: 0x" + std::to_wstring(fwRule->dwProfiles) + L"\n";
		result += L"Direction: " + ToString(fwRule->Direction) + L"\n";
		result += L"IP Protocol: " + ToString(static_cast<NET_FW_IP_PROTOCOL>(fwRule->wIpProtocol)) + L"\n";

		switch (fwRule->wIpProtocol)
		{
		case NET_FW_IP_PROTOCOL_TCP:
		case NET_FW_IP_PROTOCOL_UDP:
		{
			// TCP/UDP ports
			result += L"Local Port Keywords: 0x" + std::to_wstring(fwRule->LocalPorts.wPortKeywords) + L"\n";
			result += L"Local Ports: ";
			if (fwRule->LocalPorts.Ports.dwNumEntries > 0 && fwRule->LocalPorts.Ports.pPorts)
			{
				for (DWORD i = 0; i < fwRule->LocalPorts.Ports.dwNumEntries; ++i)
				{
					result += std::to_wstring(fwRule->LocalPorts.Ports.pPorts[i].wBegin);
					if (fwRule->LocalPorts.Ports.pPorts[i].wBegin != fwRule->LocalPorts.Ports.pPorts[i].wEnd)
					{
						result += L"-" + std::to_wstring(fwRule->LocalPorts.Ports.pPorts[i].wEnd);
					}
					if (i < fwRule->LocalPorts.Ports.dwNumEntries - 1)
					{
						result += L", ";
					}
				}
			}
			else
			{
				result += L"(none)";
			}
			result += L"\n";

			result += L"Remote Port Keywords: 0x" + std::to_wstring(fwRule->RemotePorts.wPortKeywords) + L"\n";
			result += L"Remote Ports: ";
			if (fwRule->RemotePorts.Ports.dwNumEntries > 0 && fwRule->RemotePorts.Ports.pPorts)
			{
				for (DWORD i = 0; i < fwRule->RemotePorts.Ports.dwNumEntries; ++i)
				{
					result += std::to_wstring(fwRule->RemotePorts.Ports.pPorts[i].wBegin);
					if (fwRule->RemotePorts.Ports.pPorts[i].wBegin != fwRule->RemotePorts.Ports.pPorts[i].wEnd)
					{
						result += L"-" + std::to_wstring(fwRule->RemotePorts.Ports.pPorts[i].wEnd);
					}
					if (i < fwRule->RemotePorts.Ports.dwNumEntries - 1)
					{
						result += L", ";
					}
				}
			}
			else
			{
				result += L"(none)";
			}
			result += L"\n";
			break;
		}
		case 1:
		case 58:
		{
			// ICMP
			result += L"ICMP v4 Type/Code List: ";
			if (fwRule->V4TypeCodeList.dwNumEntries > 0 && fwRule->V4TypeCodeList.pEntries)
			{
				for (DWORD i = 0; i < fwRule->V4TypeCodeList.dwNumEntries; ++i)
				{
					result += std::to_wstring(fwRule->V4TypeCodeList.pEntries[i].bType) + L":" +
						std::to_wstring(fwRule->V4TypeCodeList.pEntries[i].wCode);
					if (i < fwRule->V4TypeCodeList.dwNumEntries - 1)
					{
						result += L", ";
					}
				}
			}
			else
			{
				result += L"(none)";
			}
			result += L"\n";

			result += L"ICMP v6 Type/Code List: ";
			if (fwRule->V6TypeCodeList.dwNumEntries > 0 && fwRule->V6TypeCodeList.pEntries)
			{
				for (DWORD i = 0; i < fwRule->V6TypeCodeList.dwNumEntries; ++i)
				{
					result += std::to_wstring(fwRule->V6TypeCodeList.pEntries[i].bType) + L":" +
						std::to_wstring(fwRule->V6TypeCodeList.pEntries[i].wCode);
					if (i < fwRule->V6TypeCodeList.dwNumEntries - 1)
					{
						result += L", ";
					}
				}
			}
			else
			{
				result += L"(none)";
			}
			result += L"\n";
			break;
		}
		}

		if (fwRule->LocalAddresses.dwV4AddressKeywords > 0)
		{
			result += L"Local Address V4 Keywords: 0x" + std::to_wstring(fwRule->LocalAddresses.dwV4AddressKeywords) + L"\n";
		}
		if (fwRule->LocalAddresses.dwV6AddressKeywords > 0)
		{
			result += L"Local Address V6 Keywords: 0x" + std::to_wstring(fwRule->LocalAddresses.dwV6AddressKeywords) + L"\n";
		}
		if (fwRule->LocalAddresses.V4SubNets.dwNumEntries > 0)
		{
			result += L"Local Address : V4 Subnets: " + std::to_wstring(fwRule->LocalAddresses.V4SubNets.dwNumEntries) + L" entries\n";
		}
		if (fwRule->LocalAddresses.V6SubNets.dwNumEntries > 0)
		{
			result += L"Local Address : V6 Subnets: " + std::to_wstring(fwRule->LocalAddresses.V6SubNets.dwNumEntries) + L" entries\n";
		}
		if (fwRule->LocalAddresses.V4Ranges.dwNumEntries > 0)
		{
			result += L"Local Address : V4 Ranges: " + std::to_wstring(fwRule->LocalAddresses.V4Ranges.dwNumEntries) + L" entries\n";
		}
		if (fwRule->LocalAddresses.V6Ranges.dwNumEntries > 0)
		{
			result += L"Local Address : V6 Ranges: " + std::to_wstring(fwRule->LocalAddresses.V6Ranges.dwNumEntries) + L" entries\n";
		}

		if (fwRule->RemoteAddresses.dwV4AddressKeywords > 0)
		{
			result += L"Remote Address V4 Keywords: 0x" + std::to_wstring(fwRule->RemoteAddresses.dwV4AddressKeywords) + L"\n";
		}
		if (fwRule->RemoteAddresses.dwV6AddressKeywords > 0)
		{
			result += L"Remote Address V6 Keywords: 0x" + std::to_wstring(fwRule->RemoteAddresses.dwV6AddressKeywords) + L"\n";
		}
		if (fwRule->RemoteAddresses.V4SubNets.dwNumEntries > 0)
		{
			result += L"Remote Address : V4 Subnets: " + std::to_wstring(fwRule->RemoteAddresses.V4SubNets.dwNumEntries) + L" entries\n";
		}
		if (fwRule->RemoteAddresses.V6SubNets.dwNumEntries > 0)
		{
			result += L"Remote Address : V6 Subnets: " + std::to_wstring(fwRule->RemoteAddresses.V6SubNets.dwNumEntries) + L" entries\n";
		}
		if (fwRule->RemoteAddresses.V4Ranges.dwNumEntries > 0)
		{
			result += L"Remote Address : V4 Ranges: " + std::to_wstring(fwRule->RemoteAddresses.V4Ranges.dwNumEntries) + L" entries\n";
		}
		if (fwRule->RemoteAddresses.V6Ranges.dwNumEntries > 0)
		{
			result += L"Remote Address : V6 Ranges: " + std::to_wstring(fwRule->RemoteAddresses.V6Ranges.dwNumEntries) + L" entries\n";
		}
		if (fwRule->LocalInterfaceIds.dwNumLUIDs > 0)
		{
			result += L"Local Interface IDs: " + std::to_wstring(fwRule->LocalInterfaceIds.dwNumLUIDs) + L" entries\n";
		}

		if (fwRule->dwLocalInterfaceTypes > 0)
		{
			result += L"Local Interface Types: 0x" + std::to_wstring(fwRule->dwLocalInterfaceTypes) + L"\n";
		}

		if (fwRule->wszLocalApplication)
		{
			result += std::wstring(L"Local Application: ") + fwRule->wszLocalApplication + L"\n";
		}

		if (fwRule->wszLocalService)
		{
			result += std::wstring(L"Local Service: ") + fwRule->wszLocalService + L"\n";
		}

		result += L"Action: " + ToString(fwRule->Action) + L"\n";
		result += L"Flags: " + ToString(static_cast<FW_RULE_FLAG>(fwRule->wFlags)) + L" (0x" + std::to_wstring(fwRule->wFlags) + L")\n";
		if (fwRule->wFlags2 > 0)
		{
			result += L"Flags2: " + ToString(static_cast<FW_RULE_FLAGS2>(fwRule->wFlags2)) + L" (0x" + std::to_wstring(fwRule->wFlags2) + L")\n";
		}

		if (fwRule->wszRemoteMachineAuthorizationList)
		{
			result += std::wstring(L"Remote Machine Authorization List : ") + fwRule->wszRemoteMachineAuthorizationList + L"\n";
		}

		if (fwRule->wszRemoteUserAuthorizationList)
		{
			result += std::wstring(L"Remote User Authorization List: ") + fwRule->wszRemoteUserAuthorizationList + L"\n";
		}

		if (fwRule->wszLocalUserAuthorizationList)
		{
			result += std::wstring(L"Local User Authorization List: ") + fwRule->wszLocalUserAuthorizationList + L"\n";
		}

		if (fwRule->wszEmbeddedContext)
		{
			result += std::wstring(L"Embedded Context: ") + fwRule->wszEmbeddedContext + L"\n";
		}

		if (fwRule->PlatformValidityList.dwNumEntries > 0)
		{
			result += L"Platform Validity List: " + std::to_wstring(fwRule->PlatformValidityList.dwNumEntries) + L" entries\n";
			for (uint32_t count = 0; count < fwRule->PlatformValidityList.dwNumEntries; ++count)
			{
				result += L"  - " + ToString(fwRule->PlatformValidityList.pPlatforms[count]) + L"\n";
			}
		}

		result += L"Status: ";
		if (fwRule->Status == FW_RULE_STATUS_OK)
		{
			result += L"FW_RULE_STATUS_OK";
		}
		else
		{
			result += std::to_wstring(fwRule->Status);
		}
		result += L"\n";

		result += L"Origin: " + ToString(fwRule->Origin) + L"\n";

		if (fwRule->wszGPOName)
		{
			result += std::wstring(L"GPO Name: ") + fwRule->wszGPOName + L"\n";
		}

		if (fwRule->pMetaData)
		{
			result += L"MetaData: " + std::to_wstring(fwRule->pMetaData->dwNumEntries) + L" entries\n";
		}

		if (fwRule->wszPackageId)
		{
			result += std::wstring(L"Package ID: ") + fwRule->wszPackageId + L"\n";
		}

		if (fwRule->wszLocalUserOwner)
		{
			result += std::wstring(L"Local User Owner: ") + fwRule->wszLocalUserOwner + L"\n";
		}

		if (fwRule->dwTrustTupleKeywords > 0)
		{
			result += L"Trust Tuple Keywords: 0x" + std::to_wstring(fwRule->dwTrustTupleKeywords) + L"\n";
		}

		if (fwRule->OnNetworkNames.dwNumEntries > 0)
		{
			result += L"Network Names: ";
			for (DWORD i = 0; i < fwRule->OnNetworkNames.dwNumEntries; ++i)
			{
				result += fwRule->OnNetworkNames.wszNames[i] ? std::wstring(fwRule->OnNetworkNames.wszNames[i]) : L"(null)";
				if (i < fwRule->OnNetworkNames.dwNumEntries - 1)
				{
					result += L", ";
				}
			}
			result += L"\n";
		}

		if (fwRule->wszSecurityRealmId)
		{
			result += std::wstring(L"Security Realm ID: ") + fwRule->wszSecurityRealmId + L"\n";
		}

		if (fwRule->RemoteOutServerNames.dwNumEntries > 0)
		{
			result += L"Remote Out Server Names: ";
			for (DWORD i = 0; i < fwRule->RemoteOutServerNames.dwNumEntries; ++i)
			{
				result += fwRule->RemoteOutServerNames.wszNames[i] ? std::wstring(fwRule->RemoteOutServerNames.wszNames[i]) : L"(null)";
				if (i < fwRule->RemoteOutServerNames.dwNumEntries - 1)
				{
					result += L", ";
				}
			}
			result += L"\n";
		}

		if (fwRule->wszFqbn)
		{
			result += std::wstring(L"FQBN: ") + fwRule->wszFqbn + L"\n";
		}

		if (fwRule->compartmentId > 0)
		{
			result += L"Compartment ID: " + std::to_wstring(fwRule->compartmentId) + L"\n";
		}

		return result;
	}

private:

	static void ProcessForStringResource(std::wstring& string_value)
	{
		if (!string_value.starts_with(L"@"))
		{
			return;
		}

		if (IsRuleAnAppxRule(string_value))
		{
			return;
		}

		const auto comma = string_value.find(L',');
		if (comma == std::wstring::npos)
		{
			return;
		}

		const auto file_name = string_value.substr(1, comma - 1);
		auto string_index = string_value.substr(comma + 1);

		const auto expanded_file_name = ExpandString(file_name);
		if (expanded_file_name.empty())
		{
			if (VerboseOutputEnabled())
			{
				std::printf("Failed to expand the file name '%ls'\n", file_name.c_str());
			}
			return;
		}

		const wil::unique_hmodule file_name_hmod{ LoadLibraryExW(expanded_file_name.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE) };
		if (!file_name_hmod)
		{
			const auto gle = GetLastError();
			if (VerboseOutputEnabled())
			{
				std::printf("Failed to LoadLibraryExW(%ls) (0x%lx)\n", expanded_file_name.c_str(), gle);
			}
			return;
		}

		uint32_t converted_value = 0;
		const auto conversion_error = wil::ResultFromException([&] {
			// strip the leading '-' from the string index if it exists
			if (string_index.starts_with(L'-'))
			{
				string_index = string_index.substr(1, string_index.size() - 1);
			}
			converted_value = std::stoul(string_index);
			});
		if (FAILED(conversion_error))
		{
			if (VerboseOutputEnabled())
			{
				std::printf("Failed to convert string index '%ls' to a number: 0x%lx\n", string_index.c_str(), conversion_error);  // NOLINT(clang-diagnostic-format)
			}
			return;
		}

		// try to load the string resource
		PCWSTR raw_pointer_to_resource{ nullptr };
		const auto conversion_size = LoadStringW(
			file_name_hmod.get(),
			converted_value,
			reinterpret_cast<LPWSTR>(&raw_pointer_to_resource),
			0);
		if (conversion_size == 0)
		{
			const auto gle = GetLastError();
			if (VerboseOutputEnabled())
			{
				std::printf("Failed to LoadStringW(%ls, %u) (0x%lx)\n", expanded_file_name.c_str(), converted_value, gle);
			}
			return;
		}

		std::wstring string_resource{ raw_pointer_to_resource, raw_pointer_to_resource + conversion_size };
		string_value.swap(string_resource);
	}

	static bool IsRuleAnAppxRule(const std::wstring& rule_name)
	{
		// 16 == length of '@{' (2) + length of 'ms-resource://' (14)
		constexpr size_t minRuleNameLength = 16;
		if (rule_name.length() < minRuleNameLength)
		{
			return false;
		}
		if (rule_name[0] != L'@' || rule_name[1] != '{')
		{
			return false;
		}

		// now search for ms-resource://  --- this is case-sensitive, but that seems correct for APPX rules
		constexpr auto* appxResourceStringId = L"ms-resource://";
		return rule_name.find(appxResourceStringId) != std::wstring::npos;
	}

	static std::wstring ExpandString(const std::wstring& original_filename)
	{
		// resolve any environment variables in the string, then verify it exists
		std::wstring expanded_string;
		expanded_string.resize(original_filename.size() + 10, L' ');

		for (;;)
		{
			const auto expanded_size = ExpandEnvironmentStringsW(original_filename.c_str(), expanded_string.data(), static_cast<DWORD>(expanded_string.size()));
			if (expanded_size == 0)
			{
				const auto gle = GetLastError();
				if (VerboseOutputEnabled())
				{
					std::printf("Failed to ExpandEnvironmentStrings(%ls) (0x%lx)", original_filename.c_str(), gle);
				}
				return {};
			}

			if (expanded_size <= expanded_string.size())
			{
				// the string was expanded, and it fits in the buffer
				expanded_string.resize(expanded_size - 1); // trim the null terminator
				break;
			}

			expanded_string.resize(expanded_size, L' '); // the buffer was not big enough, resize it and try again
		}

		return expanded_string;
	}

	void ProcessLocalUserSid()
	{
		if (fwRule->wszLocalUserOwner)
		{
			// process the local user owner string for string resources
			wil::unique_sid localUserOwnerSid;
			if (!ConvertStringSidToSid(fwRule->wszLocalUserOwner, localUserOwnerSid.addressof()))
			{
				const auto gle = GetLastError();
				if (VerboseOutputEnabled())
				{
					std::printf("Failed to ConvertStringSidToSid(%ls) (0x%lx)\n", fwRule->wszLocalUserOwner, gle);
				}
				userNameResolvedSuccessfully = false;
				return;
			}

			DWORD localUserOwnerNameSize = 0;
			DWORD cchReferencedDomainName = 0;
			SID_NAME_USE sid_name_use{};
			if (!LookupAccountSidW(nullptr, localUserOwnerSid.get(), localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
			{
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					localUserOwnerName.resize(localUserOwnerNameSize);
					localUserDomainName.resize(cchReferencedDomainName);

					if (!LookupAccountSidW(nullptr, localUserOwnerSid.get(), localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
					{
						const auto gle = GetLastError();
						if (DebugOutputEnabled())
						{
							std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", fwRule->wszLocalUserOwner, gle);
						}
						userNameResolvedSuccessfully = false;
						return;
					}

					userNameResolvedSuccessfully = true;

					if (DebugOutputEnabled())
					{
						if (localUserDomainName.empty())
						{
							std::printf("Successfully converted LocalUserOwner SID %ls to %ls\n", fwRule->wszLocalUserOwner, localUserOwnerName.c_str());
						}
						else
						{
							std::printf("Successfully converted LocalUserOwner SID %ls to %ls\\%ls\n", fwRule->wszLocalUserOwner, localUserDomainName.c_str(), localUserOwnerName.c_str());
						}
					}
				}
				else
				{
					const auto gle = GetLastError();
					if (DebugOutputEnabled())
					{
						std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", fwRule->wszLocalUserOwner, gle);
					}
					userNameResolvedSuccessfully = false;
				}
			}
			else
			{
				// should never happen
				FAIL_FAST();
			}
		}
	}

	void CheckIfFileExists()
	{
		if (!fwRule->wszLocalApplication)
		{
			return;
		}

		const std::wstring original_filename{ fwRule->wszLocalApplication };
		if (IsRuleAnAppxRule(fwRule->wszLocalApplication))
		{
			// appx rules must be checked using appx APIs to check for that package
			return;
		}

		if (CompareStringOrdinal(fwRule->wszLocalApplication, -1, L"SYSTEM", -1, TRUE) == CSTR_EQUAL)
		{
			// this refers to a kernel component
			return;
		}

		const auto expanded_string = ExpandString(original_filename);
		if (expanded_string.empty())
		{
			// failed to expand the string, cannot check if it exists
			return;
		}

		// now check if the file exists
		WIN32_FIND_DATA find_data{};
		HANDLE found_file = FindFirstFileExW(
			expanded_string.c_str(),
			FindExInfoBasic,
			&find_data,
			FindExSearchNameMatch,
			nullptr,
			0);
		if (found_file == INVALID_HANDLE_VALUE)
		{
			const auto gle = GetLastError();
			if (DebugOutputEnabled())
			{
				std::printf("Failed to FindFirstFileExW(%ls) (0x%lx)\n", expanded_string.c_str(), gle);
			}
			targetApplicationExists = false;
		}
		else
		{
			targetApplicationExists = true;
			FindClose(found_file);
		}
	}

	void AppendValue(const GUID& guid)
	{
		AppendValue(guid.Data1);
		AppendValue(guid.Data2);
		AppendValue(guid.Data3);
		// append as 1 64-bit integer
		static_assert(sizeof(guid.Data4) == sizeof(uint64_t));
		const unsigned char* data4 = guid.Data4;
		const uint64_t* data4_as_uint64 = reinterpret_cast<const uint64_t*>(data4);
		AppendValue(*data4_as_uint64);
	}

	void AppendValue(const FW_PORT_RANGE_LIST& list)
	{
		const auto* ports = list.pPorts;
		const auto ports_count = list.dwNumEntries;
		if (ports_count == 0 || !ports)
		{
			if (ports_count != 0 || ports)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& port : wil::make_range(ports, ports + ports_count))
			{
				AppendValue(port.wBegin);
				AppendValue(port.wEnd);
			}
		}
	}

	void AppendValue(const FW_ICMP_TYPE_CODE_LIST& list)
	{
		const auto* icmp_list = list.pEntries;
		const auto icmp_count = list.dwNumEntries;
		if (icmp_count == 0 || !icmp_list)
		{
			if (icmp_count != 0 || icmp_list)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& icmp : wil::make_range(icmp_list, icmp_list + icmp_count))
			{
				AppendValue(icmp.bType);
				AppendValue(icmp.wCode);
			}
		}
	}

	void AppendValue(const FW_IPV4_SUBNET_LIST& list)
	{
		const auto* subnets = list.pSubNets;
		const auto subnet_count = list.dwNumEntries;
		if (subnet_count == 0 || !subnets)
		{
			if (subnet_count != 0 || subnets)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& subnet : wil::make_range(subnets, subnets + subnet_count))
			{
				AppendValue(subnet.dwAddress);
				AppendValue(subnet.dwSubNetMask);
			}
		}
	}

	void AppendValue(const FW_IPV6_SUBNET_LIST& list)
	{
		const auto* subnets = list.pSubNets;
		const auto subnet_count = list.dwNumEntries;
		if (subnet_count == 0 || !subnets)
		{
			if (subnet_count != 0 || subnets)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& subnet : wil::make_range(subnets, subnets + subnet_count))
			{
				// append as 2 64-bit integers
				static_assert(sizeof(subnet.Address) == (2 * sizeof(uint64_t)));
				const BYTE* address_buffer = subnet.Address;
				const uint64_t* first_integer = reinterpret_cast<const uint64_t*>(address_buffer);
				AppendValue(*first_integer);
				const uint64_t* second_integer = reinterpret_cast<const uint64_t*>(address_buffer + sizeof(first_integer));
				AppendValue(*second_integer);
			}
		}
	}

	void AppendValue(const FW_IPV4_RANGE_LIST& list)
	{
		const auto* ranges = list.pRanges;
		const auto range_count = list.dwNumEntries;
		if (range_count == 0 || !ranges)
		{
			if (range_count != 0 || ranges)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& range : wil::make_range(ranges, ranges + range_count))
			{
				AppendValue(range.dwBegin);
				AppendValue(range.dwEnd);
			}
		}
	}

	void AppendValue(const FW_IPV6_RANGE_LIST& list)
	{
		const auto* ranges = list.pRanges;
		const auto range_count = list.dwNumEntries;
		if (range_count == 0 || !ranges)
		{
			if (range_count != 0 || ranges)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& range : wil::make_range(ranges, ranges + range_count))
			{
				// append as 2 64-bit integers
				static_assert(sizeof(range.Begin) == (2 * sizeof(uint64_t)));
				const BYTE* begin_buffer = range.Begin;
				const uint64_t* first_begin_integer = reinterpret_cast<const uint64_t*>(begin_buffer);
				AppendValue(*first_begin_integer);
				const uint64_t* second_begin_integer = reinterpret_cast<const uint64_t*>(begin_buffer + sizeof(first_begin_integer));
				AppendValue(*second_begin_integer);
				// append as 2 64-bit integers
				static_assert(sizeof(range.End) == (2 * sizeof(uint64_t)));
				const BYTE* end_buffer = range.End;
				const uint64_t* first_end_integer = reinterpret_cast<const uint64_t*>(end_buffer);
				AppendValue(*first_end_integer);
				const uint64_t* second_end_integer = reinterpret_cast<const uint64_t*>(end_buffer + sizeof(first_end_integer));
				AppendValue(*second_end_integer);
			}
		}
	}

	void AppendValue(const FW_INTERFACE_LUIDS& interface_luids)
	{
		const auto* luids = interface_luids.pLUIDs;
		const auto luids_count = interface_luids.dwNumLUIDs;
		if (luids_count == 0 || !luids)
		{
			if (luids_count != 0 || luids)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& luid : wil::make_range(luids, luids + luids_count))
			{
				AppendValue(luid);
			}
		}
	}

	void AppendValue(const FW_OS_PLATFORM_LIST& list)
	{
		const auto* platforms = list.pPlatforms;
		const auto platform_count = list.dwNumEntries;
		if (platform_count == 0 || !platforms)
		{
			if (platform_count != 0 || platforms)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& platform : wil::make_range(platforms, platforms + platform_count))
			{
				AppendValue(platform.bPlatform);
				AppendValue(platform.bMajorVersion);
				AppendValue(platform.bMinorVersion);
				AppendValue(platform.Reserved);
			}
		}
	}

	// ReSharper disable once CppParameterMayBeConstPtrOrRef
	// cannot be a const pointer, as the pointer value in the rule is not const
	void AppendValue(FW_OBJECT_METADATA* pMetadata)
	{
		if (!pMetadata)
		{
			AppendValue(L"null,");
			return;
		}

		const auto* enforcement_states = pMetadata->pEnforcementStates;
		const auto enforcement_states_count = pMetadata->dwNumEntries;

		AppendValue(pMetadata->qwFilterContextID);

		if (enforcement_states_count == 0 || !enforcement_states)
		{
			if (enforcement_states_count != 0 || enforcement_states)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& state : wil::make_range(enforcement_states, enforcement_states + enforcement_states_count))
			{
				AppendValue(state);
			}
		}
	}

	void AppendValue(const FW_NETWORK_NAMES& network_names)
	{
		const auto* names = network_names.wszNames;
		const auto names_count = network_names.dwNumEntries;

		if (names_count == 0 || !names)
		{
			if (names_count != 0 || names)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& name : wil::make_range(names, names + names_count))
			{
				AppendValue(name);
			}
		}
	}

	void AppendValue(PCWSTR value)
	{
		if (!value || value[0] == L'\0')
		{
			normalizedRuleDetails.value.append(L"null,");
			return;
		}

		NormalizedString normalized_string = NormalizedString::Normalize(value);
		normalized_string.value += L',';

		normalizedRuleDetails += normalized_string;
	}

	void AppendValue(PWSTR value)
	{
		const PCWSTR const_value{ value };
		return AppendValue(const_value);
	}

	template <typename T>
	void AppendValue(T t)
	{
		// convert any integer type T
		const auto convertedValue = static_cast<uint64_t>(t);
		normalizedRuleDetails.value.append(std::to_wstring(convertedValue) + L',');
	}
};

// returns the same integer value as memcmp()
// -1 if lhs < rhs, 0 if equal, +1 if lhs > rhs
inline int RuleDetailsComparison(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs.normalizedRuleDetails, rhs.normalizedRuleDetails);
}
