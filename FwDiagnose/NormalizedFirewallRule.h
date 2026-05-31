// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <Windows.h>

#include "firewall.h"
#include "NormalizedString.h"
#include "WfpCounters.h"

struct NormalizedFirewallRule
{
	NormalizedFirewallRule(const FW_RULE* fwRule, WORD requestedRuleVersion);

	const FW_RULE* fw_rule{};
	WORD requested_rule_version{};
	std::wstring rule_id{};
	NormalizedString rule_name{ NormalizedString::Create(L"") };
	std::wstring rule_description{};

	NormalizedString normalized_rule_details{ NormalizedString::Create(L"") };
	NormalizedString normalized_package_family_name{ NormalizedString::Create(L"") };

	std::wstring local_user_owner_name{};
	std::wstring local_user_domain_name{};
	std::optional<bool> successfully_resolved_user_name{ std::nullopt };
	std::optional<bool> successfully_resolved_user_name_with_local_profile{ std::nullopt };

	std::optional<bool> target_application_exists{ std::nullopt };

	size_t filter_count{};
	size_t filter_condition_count{};
	size_t duplicate_rule_count{};

	bool is_rule_enabled = false;
	bool is_rule_deleted = false;
	bool missing_package_id = false;
	bool missing_package_family_name = false;
	bool unresolve_user_sid = false;

	NormalizedFirewallRule(const NormalizedFirewallRule&) = delete;
	NormalizedFirewallRule& operator=(const NormalizedFirewallRule&) = delete;

	NormalizedFirewallRule(NormalizedFirewallRule&&) noexcept = default;
	NormalizedFirewallRule& operator=(NormalizedFirewallRule&&) noexcept = default;

	~NormalizedFirewallRule() = default;

	std::wstring PrintRule() const;

private:
	void CheckIfFileExists();
	void ProcessLocalUserSid();

	void AppendValue(const GUID& guid);
	void AppendValue(const FW_PORT_RANGE_LIST& list);
	void AppendValue(const FW_ICMP_TYPE_CODE_LIST& list);

	void AppendValue(const FW_IPV4_SUBNET_LIST& list);
	void AppendValue(const FW_IPV6_SUBNET_LIST& list);
	void AppendValue(const FW_IPV4_RANGE_LIST& list);
	void AppendValue(const FW_IPV6_RANGE_LIST& list);

	void AppendValue(const FW_INTERFACE_LUIDS& interface_luids);
	void AppendValue(const FW_OS_PLATFORM_LIST& list);
	void AppendValue(const FW_OBJECT_METADATA* pMetadata);
	void AppendValue(const FW_NETWORK_NAMES& network_names);
	void AppendValue(const FW_RULE::FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST& list);

	void AppendValue(PCWSTR value)
	{
		if (!value || value[0] == L'\0')
		{
			normalized_rule_details.value.append(L"null,");
			return;
		}

		NormalizedString normalized_string = NormalizedString::Create(value);
		normalized_string.value += L',';

		normalized_rule_details.append(std::move(normalized_string));
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
		normalized_rule_details.value.append(std::to_wstring(convertedValue) + L',');
	}
};

// returns the same integer value as memcmp()
// -1 if lhs < rhs, 0 if equal, +1 if lhs > rhs
inline int RuleDetailsComparison(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs.normalized_rule_details, rhs.normalized_rule_details);
}

enum ComparisonPolicy
{
	comparison_policy_all = 0x0,
	comparison_policy_skip_comparing_profiles = 0x1,
	comparison_policy_skip_comparing_if_enabled = 0x2,
	comparison_policy_skip_comparing_local_subnet = 0x4,
};
DEFINE_ENUM_FLAG_OPERATORS(ComparisonPolicy)

// returns the same integer value as memcmp()
// -1 if lhs < rhs, 0 if equal, +1 if lhs > rhs
inline int FwRuleDetailsComparison(const FW_RULE& lhs, const FW_RULE& rhs, ComparisonPolicy policy = ComparisonPolicy::comparison_policy_all) noexcept
{
	// check the optional fields based off the bool input parameters
	if (policy & ComparisonPolicy::comparison_policy_skip_comparing_profiles)
	{
		// don't compare dwProfiles
	}
	else if (lhs.dwProfiles != rhs.dwProfiles)
	{
		return lhs.dwProfiles < rhs.dwProfiles ? -1 : 1;
	}

	if (policy & ComparisonPolicy::comparison_policy_skip_comparing_if_enabled)
	{
		// don't match if the rules are enabled
		// remove the FW_RULE_FLAGS_ACTIVE flag from both before comparing
		const auto lhs_flags = lhs.wFlags & ~FW_RULE_FLAGS_ACTIVE;
		const auto rhs_flags = rhs.wFlags & ~FW_RULE_FLAGS_ACTIVE;
		if (lhs_flags != rhs_flags)
		{
			return lhs_flags < rhs_flags ? -1 : 1;
		}
	}
	else
	{
		if (lhs.wFlags != rhs.wFlags)
		{
			return lhs.wFlags < rhs.wFlags ? -1 : 1;
		}
	}

	if (policy & ComparisonPolicy::comparison_policy_skip_comparing_local_subnet)
	{
		// not comparing local subnets
		// remove the FW_ADDRESS_KEYWORD_LOCAL_SUBNET flag from both before comparing

		const auto lhs_local_v4_keywords = lhs.LocalAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_local_v4_keywords = rhs.LocalAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if (lhs_local_v4_keywords != rhs_local_v4_keywords)
		{
			return lhs_local_v4_keywords < rhs_local_v4_keywords ? -1 : 1;
		}

		const auto lhs_local_v6_keywords = lhs.LocalAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_local_v6_keywords = rhs.LocalAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if (lhs_local_v6_keywords != rhs_local_v6_keywords)
		{
			return lhs_local_v6_keywords < rhs_local_v6_keywords ? -1 : 1;
		}

		const auto lhs_remote_v4_keywords = lhs.RemoteAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_remote_v4_keywords = rhs.RemoteAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if (lhs_remote_v4_keywords != rhs_remote_v4_keywords)
		{
			return lhs_remote_v4_keywords < rhs_remote_v4_keywords ? -1 : 1;
		}

		const auto lhs_remote_v6_keywords = lhs.RemoteAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_remote_v6_keywords = rhs.RemoteAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if (lhs_remote_v6_keywords != rhs_remote_v6_keywords)
		{
			return lhs_remote_v6_keywords < rhs_remote_v6_keywords ? -1 : 1;
		}
	}
	else
	{
		if (lhs.LocalAddresses.dwV4AddressKeywords != rhs.LocalAddresses.dwV4AddressKeywords)
		{
			return lhs.LocalAddresses.dwV4AddressKeywords < rhs.LocalAddresses.dwV4AddressKeywords ? -1 : 1;
		}
		if (lhs.LocalAddresses.dwV6AddressKeywords != rhs.LocalAddresses.dwV6AddressKeywords)
		{
			return lhs.LocalAddresses.dwV6AddressKeywords < rhs.LocalAddresses.dwV6AddressKeywords ? -1 : 1;
		}
		if (lhs.RemoteAddresses.dwV4AddressKeywords != rhs.RemoteAddresses.dwV4AddressKeywords)
		{
			return lhs.RemoteAddresses.dwV4AddressKeywords < rhs.RemoteAddresses.dwV4AddressKeywords ? -1 : 1;
		}
		if (lhs.RemoteAddresses.dwV6AddressKeywords != rhs.RemoteAddresses.dwV6AddressKeywords)
		{
			return lhs.RemoteAddresses.dwV6AddressKeywords < rhs.RemoteAddresses.dwV6AddressKeywords ? -1 : 1;
		}
	}

	// compare integer types first
	if (lhs.Direction != rhs.Direction)
	{
		return lhs.Direction < rhs.Direction ? -1 : 1;
	}

	if (lhs.wIpProtocol != rhs.wIpProtocol)
	{
		return lhs.wIpProtocol < rhs.wIpProtocol ? -1 : 1;
	}

	if (lhs.wIpProtocol == 6 || lhs.wIpProtocol == 17) // TCP or UDP
	{
		if (lhs.LocalPorts.wPortKeywords != rhs.LocalPorts.wPortKeywords)
		{
			return lhs.LocalPorts.wPortKeywords < rhs.LocalPorts.wPortKeywords ? -1 : 1;
		}
		if (lhs.RemotePorts.wPortKeywords != rhs.RemotePorts.wPortKeywords)
		{
			return lhs.RemotePorts.wPortKeywords < rhs.RemotePorts.wPortKeywords ? -1 : 1;
		}

		if (lhs.LocalPorts.Ports.dwNumEntries != rhs.LocalPorts.Ports.dwNumEntries)
		{
			return lhs.LocalPorts.Ports.dwNumEntries < rhs.LocalPorts.Ports.dwNumEntries ? -1 : 1;
		}
		if (lhs.RemotePorts.Ports.dwNumEntries != rhs.RemotePorts.Ports.dwNumEntries)
		{
			return lhs.RemotePorts.Ports.dwNumEntries < rhs.RemotePorts.Ports.dwNumEntries ? -1 : 1;
		}

		if (!lhs.LocalPorts.Ports.pPorts && !rhs.LocalPorts.Ports.pPorts)
		{
			// both are null, considered equal, continue comparison
		}
		else if (lhs.LocalPorts.Ports.pPorts && rhs.LocalPorts.Ports.pPorts)
		{
			for (DWORD i = 0; i < lhs.LocalPorts.Ports.dwNumEntries; ++i)
			{
				if (lhs.LocalPorts.Ports.pPorts[i].wBegin != rhs.LocalPorts.Ports.pPorts[i].wBegin)
				{
					return lhs.LocalPorts.Ports.pPorts[i].wBegin < rhs.LocalPorts.Ports.pPorts[i].wBegin ? -1 : 1;
				}
				if (lhs.LocalPorts.Ports.pPorts[i].wEnd != rhs.LocalPorts.Ports.pPorts[i].wEnd)
				{
					return lhs.LocalPorts.Ports.pPorts[i].wEnd < rhs.LocalPorts.Ports.pPorts[i].wEnd ? -1 : 1;
				}
			}
		}
		else
		{
			return lhs.LocalPorts.Ports.pPorts ? 1 : -1; // one is null, the other is not
		}
	}
	else if (lhs.wIpProtocol == 1) // ICMP
	{
		if (lhs.V4TypeCodeList.dwNumEntries != rhs.V4TypeCodeList.dwNumEntries)
		{
			return lhs.V4TypeCodeList.dwNumEntries < rhs.V4TypeCodeList.dwNumEntries ? -1 : 1;
		}

		if (!lhs.V4TypeCodeList.pEntries && !rhs.V4TypeCodeList.pEntries)
		{
			// both are null, considered equal, continue comparison
		}
		else if (lhs.V4TypeCodeList.pEntries && rhs.V4TypeCodeList.pEntries)
		{
			for (DWORD i = 0; i < lhs.V4TypeCodeList.dwNumEntries; ++i)
			{
				if (lhs.V4TypeCodeList.pEntries[i].bType != rhs.V4TypeCodeList.pEntries[i].bType)
				{
					return lhs.V4TypeCodeList.pEntries[i].bType < rhs.V4TypeCodeList.pEntries[i].bType ? -1 : 1;
				}
				if (lhs.V4TypeCodeList.pEntries[i].wCode != rhs.V4TypeCodeList.pEntries[i].wCode)
				{
					return lhs.V4TypeCodeList.pEntries[i].wCode < rhs.V4TypeCodeList.pEntries[i].wCode ? -1 : 1;
				}
			}
		}
		else
		{
			return lhs.V4TypeCodeList.pEntries ? 1 : -1; // one is null, the other is not
		}
	}
	else if (lhs.wIpProtocol == 58) // ICMPv6
	{
		if (lhs.V6TypeCodeList.dwNumEntries != rhs.V6TypeCodeList.dwNumEntries)
		{
			return lhs.V6TypeCodeList.dwNumEntries < rhs.V6TypeCodeList.dwNumEntries ? -1 : 1;
		}

		if (!lhs.V6TypeCodeList.pEntries && !rhs.V6TypeCodeList.pEntries)
		{
			// both are null, considered equal, continue comparison
		}
		else if (lhs.V6TypeCodeList.pEntries && rhs.V6TypeCodeList.pEntries)
		{
			for (DWORD i = 0; i < lhs.V6TypeCodeList.dwNumEntries; ++i)
			{
				if (lhs.V6TypeCodeList.pEntries[i].bType != rhs.V6TypeCodeList.pEntries[i].bType)
				{
					return lhs.V6TypeCodeList.pEntries[i].bType < rhs.V6TypeCodeList.pEntries[i].bType ? -1 : 1;
				}
				if (lhs.V6TypeCodeList.pEntries[i].wCode != rhs.V6TypeCodeList.pEntries[i].wCode)
				{
					return lhs.V6TypeCodeList.pEntries[i].wCode < rhs.V6TypeCodeList.pEntries[i].wCode ? -1 : 1;
				}
			}
		}
		else
		{
			return lhs.V6TypeCodeList.pEntries ? 1 : -1; // one is null, the other is not
		}
	}

	if (lhs.LocalAddresses.V4Ranges.dwNumEntries != rhs.LocalAddresses.V4Ranges.dwNumEntries)
	{
		return lhs.LocalAddresses.V4Ranges.dwNumEntries < rhs.LocalAddresses.V4Ranges.dwNumEntries ? -1 : 1;
	}
	if (lhs.LocalAddresses.V6Ranges.dwNumEntries != rhs.LocalAddresses.V6Ranges.dwNumEntries)
	{
		return lhs.LocalAddresses.V6Ranges.dwNumEntries < rhs.LocalAddresses.V6Ranges.dwNumEntries ? -1 : 1;
	}
	if (!lhs.LocalAddresses.V4Ranges.pRanges && !rhs.LocalAddresses.V4Ranges.pRanges)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.LocalAddresses.V4Ranges.pRanges && rhs.LocalAddresses.V4Ranges.pRanges)
	{
		for (DWORD i = 0; i < lhs.LocalAddresses.V4Ranges.dwNumEntries; ++i)
		{
			const auto& lhsRange = lhs.LocalAddresses.V4Ranges.pRanges[i];
			const auto& rhsRange = rhs.LocalAddresses.V4Ranges.pRanges[i];
			if (lhsRange.dwBegin != rhsRange.dwBegin)
			{
				return lhsRange.dwBegin < rhsRange.dwBegin ? -1 : 1;
			}
			if (lhsRange.dwEnd != rhsRange.dwEnd)
			{
				return lhsRange.dwEnd < rhsRange.dwEnd ? -1 : 1;
			}
		}
	}
	else
	{
		return lhs.LocalAddresses.V4Ranges.pRanges ? 1 : -1; // one is null, the other is not
	}
	if (!lhs.LocalAddresses.V6Ranges.pRanges && !rhs.LocalAddresses.V6Ranges.pRanges)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.LocalAddresses.V6Ranges.pRanges && rhs.LocalAddresses.V6Ranges.pRanges)
	{
		for (DWORD i = 0; i < lhs.LocalAddresses.V6Ranges.dwNumEntries; ++i)
		{
			const auto& lhsRange = lhs.LocalAddresses.V6Ranges.pRanges[i];
			const auto& rhsRange = rhs.LocalAddresses.V6Ranges.pRanges[i];
			auto cmp = memcmp(&lhsRange.Begin, &rhsRange.Begin, sizeof(lhsRange.Begin));
			if (cmp != 0)
			{
				return cmp;
			}
			cmp = memcmp(&lhsRange.End, &rhsRange.End, sizeof(lhsRange.End));
			if (cmp != 0)
			{
				return cmp;
			}
		}
	}
	else
	{
		return lhs.LocalAddresses.V6Ranges.pRanges ? 1 : -1; // one is null, the other is not
	}
	if (lhs.LocalAddresses.V4SubNets.dwNumEntries != rhs.LocalAddresses.V4SubNets.dwNumEntries)
	{
		return lhs.LocalAddresses.V4SubNets.dwNumEntries < rhs.LocalAddresses.V4SubNets.dwNumEntries ? -1 : 1;
	}
	if (lhs.LocalAddresses.V6SubNets.dwNumEntries != rhs.LocalAddresses.V6SubNets.dwNumEntries)
	{
		return lhs.LocalAddresses.V6SubNets.dwNumEntries < rhs.LocalAddresses.V6SubNets.dwNumEntries ? -1 : 1;
	}
	if (!lhs.LocalAddresses.V4SubNets.pSubNets && !rhs.LocalAddresses.V4SubNets.pSubNets)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.LocalAddresses.V4SubNets.pSubNets && rhs.LocalAddresses.V4SubNets.pSubNets)
	{
		for (DWORD i = 0; i < lhs.LocalAddresses.V4SubNets.dwNumEntries; ++i)
		{
			const auto& lhsSubNet = lhs.LocalAddresses.V4SubNets.pSubNets[i];
			const auto& rhsSubNet = rhs.LocalAddresses.V4SubNets.pSubNets[i];
			if (lhsSubNet.dwAddress != rhsSubNet.dwAddress)
			{
				return lhsSubNet.dwAddress < rhsSubNet.dwAddress ? -1 : 1;
			}
			if (lhsSubNet.dwSubNetMask != rhsSubNet.dwSubNetMask)
			{
				return lhsSubNet.dwSubNetMask < rhsSubNet.dwSubNetMask ? -1 : 1;
			}
		}
	}
	else
	{
		return lhs.LocalAddresses.V4SubNets.pSubNets ? 1 : -1; // one is null, the other is not
	}
	if (!lhs.LocalAddresses.V6SubNets.pSubNets && !rhs.LocalAddresses.V6SubNets.pSubNets)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.LocalAddresses.V6SubNets.pSubNets && rhs.LocalAddresses.V6SubNets.pSubNets)
	{
		for (DWORD i = 0; i < lhs.LocalAddresses.V6SubNets.dwNumEntries; ++i)
		{
			const auto& lhsSubNet = lhs.LocalAddresses.V6SubNets.pSubNets[i];
			const auto& rhsSubNet = rhs.LocalAddresses.V6SubNets.pSubNets[i];
			int cmp = memcmp(lhsSubNet.Address, rhsSubNet.Address, sizeof(lhsSubNet.Address));
			if (cmp != 0)
			{
				return cmp;
			}
			if (lhsSubNet.dwNumPrefixBits != rhsSubNet.dwNumPrefixBits)
			{
				return lhsSubNet.dwNumPrefixBits < rhsSubNet.dwNumPrefixBits ? -1 : 1;
			}
		}
	}
	else
	{
		return lhs.LocalAddresses.V6SubNets.pSubNets ? 1 : -1; // one is null, the other is not
	}

	if (lhs.RemoteAddresses.V4Ranges.dwNumEntries != rhs.RemoteAddresses.V4Ranges.dwNumEntries)
	{
		return lhs.RemoteAddresses.V4Ranges.dwNumEntries < rhs.RemoteAddresses.V4Ranges.dwNumEntries ? -1 : 1;
	}
	if (lhs.RemoteAddresses.V6Ranges.dwNumEntries != rhs.RemoteAddresses.V6Ranges.dwNumEntries)
	{
		return lhs.RemoteAddresses.V6Ranges.dwNumEntries < rhs.RemoteAddresses.V6Ranges.dwNumEntries ? -1 : 1;
	}
	if (!lhs.RemoteAddresses.V4Ranges.pRanges && !rhs.RemoteAddresses.V4Ranges.pRanges)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.RemoteAddresses.V4Ranges.pRanges && rhs.RemoteAddresses.V4Ranges.pRanges)
	{
		for (DWORD i = 0; i < lhs.RemoteAddresses.V4Ranges.dwNumEntries; ++i)
		{
			const auto& lhsRange = lhs.RemoteAddresses.V4Ranges.pRanges[i];
			const auto& rhsRange = rhs.RemoteAddresses.V4Ranges.pRanges[i];
			if (lhsRange.dwBegin != rhsRange.dwBegin)
			{
				return lhsRange.dwBegin < rhsRange.dwBegin ? -1 : 1;
			}
			if (lhsRange.dwEnd != rhsRange.dwEnd)
			{
				return lhsRange.dwEnd < rhsRange.dwEnd ? -1 : 1;
			}
		}
	}
	else
	{
		return lhs.RemoteAddresses.V4Ranges.pRanges ? 1 : -1; // one is null, the other is not
	}
	if (!lhs.RemoteAddresses.V6Ranges.pRanges && !rhs.RemoteAddresses.V6Ranges.pRanges)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.RemoteAddresses.V6Ranges.pRanges && rhs.RemoteAddresses.V6Ranges.pRanges)
	{
		for (DWORD i = 0; i < lhs.RemoteAddresses.V6Ranges.dwNumEntries; ++i)
		{
			const auto& lhsRange = lhs.RemoteAddresses.V6Ranges.pRanges[i];
			const auto& rhsRange = rhs.RemoteAddresses.V6Ranges.pRanges[i];
			auto cmp = memcmp(&lhsRange.Begin, &rhsRange.Begin, sizeof(lhsRange.Begin));
			if (cmp != 0)
			{
				return cmp;
			}
			cmp = memcmp(&lhsRange.End, &rhsRange.End, sizeof(lhsRange.End));
			if (cmp != 0)
			{
				return cmp;
			}
		}
	}
	else
	{
		return lhs.RemoteAddresses.V6Ranges.pRanges ? 1 : -1; // one is null, the other is not
	}
	if (lhs.RemoteAddresses.V4SubNets.dwNumEntries != rhs.RemoteAddresses.V4SubNets.dwNumEntries)
	{
		return lhs.RemoteAddresses.V4SubNets.dwNumEntries < rhs.RemoteAddresses.V4SubNets.dwNumEntries ? -1 : 1;
	}
	if (lhs.RemoteAddresses.V6SubNets.dwNumEntries != rhs.RemoteAddresses.V6SubNets.dwNumEntries)
	{
		return lhs.RemoteAddresses.V6SubNets.dwNumEntries < rhs.RemoteAddresses.V6SubNets.dwNumEntries ? -1 : 1;
	}
	if (!lhs.RemoteAddresses.V4SubNets.pSubNets && !rhs.RemoteAddresses.V4SubNets.pSubNets)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.RemoteAddresses.V4SubNets.pSubNets && rhs.RemoteAddresses.V4SubNets.pSubNets)
	{
		for (DWORD i = 0; i < lhs.RemoteAddresses.V4SubNets.dwNumEntries; ++i)
		{
			const auto& lhsSubNet = lhs.RemoteAddresses.V4SubNets.pSubNets[i];
			const auto& rhsSubNet = rhs.RemoteAddresses.V4SubNets.pSubNets[i];
			if (lhsSubNet.dwAddress != rhsSubNet.dwAddress)
			{
				return lhsSubNet.dwAddress < rhsSubNet.dwAddress ? -1 : 1;
			}
			if (lhsSubNet.dwSubNetMask != rhsSubNet.dwSubNetMask)
			{
				return lhsSubNet.dwSubNetMask < rhsSubNet.dwSubNetMask ? -1 : 1;
			}
		}
	}
	else
	{
		return lhs.RemoteAddresses.V4SubNets.pSubNets ? 1 : -1; // one is null, the other is not
	}
	if (!lhs.RemoteAddresses.V6SubNets.pSubNets && !rhs.RemoteAddresses.V6SubNets.pSubNets)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.RemoteAddresses.V6SubNets.pSubNets && rhs.RemoteAddresses.V6SubNets.pSubNets)
	{
		for (DWORD i = 0; i < lhs.RemoteAddresses.V6SubNets.dwNumEntries; ++i)
		{
			const auto& lhsSubNet = lhs.RemoteAddresses.V6SubNets.pSubNets[i];
			const auto& rhsSubNet = rhs.RemoteAddresses.V6SubNets.pSubNets[i];
			const auto cmp = memcmp(lhsSubNet.Address, rhsSubNet.Address, sizeof(lhsSubNet.Address));
			if (cmp != 0)
			{
				return cmp;
			}
			if (lhsSubNet.dwNumPrefixBits != rhsSubNet.dwNumPrefixBits)
			{
				return lhsSubNet.dwNumPrefixBits < rhsSubNet.dwNumPrefixBits ? -1 : 1;
			}
		}
	}
	else
	{
		return lhs.RemoteAddresses.V6SubNets.pSubNets ? 1 : -1; // one is null, the other is not
	}

	if (lhs.LocalInterfaceIds.dwNumLUIDs != rhs.LocalInterfaceIds.dwNumLUIDs)
	{
		return lhs.LocalInterfaceIds.dwNumLUIDs < rhs.LocalInterfaceIds.dwNumLUIDs ? -1 : 1;
	}
	if (!lhs.LocalInterfaceIds.pLUIDs && !rhs.LocalInterfaceIds.pLUIDs)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.LocalInterfaceIds.pLUIDs && rhs.LocalInterfaceIds.pLUIDs)
	{
		for (DWORD i = 0; i < lhs.LocalInterfaceIds.dwNumLUIDs; ++i)
		{
			const auto& lhsLUID = lhs.LocalInterfaceIds.pLUIDs[i];
			const auto& rhsLUID = rhs.LocalInterfaceIds.pLUIDs[i];
			const auto cmp = memcmp(&lhsLUID, &rhsLUID, sizeof(lhsLUID));
			if (cmp != 0)
			{
				return cmp;
			}
		}
	}
	else
	{
		return lhs.LocalInterfaceIds.pLUIDs ? 1 : -1; // one is null, the other is not
	}

	if (lhs.dwLocalInterfaceTypes != rhs.dwLocalInterfaceTypes)
	{
		return lhs.dwLocalInterfaceTypes < rhs.dwLocalInterfaceTypes ? -1 : 1;
	}

	if (lhs.Action != rhs.Action)
	{
		return lhs.Action < rhs.Action ? -1 : 1;
	}

	if (lhs.PlatformValidityList.dwNumEntries != rhs.PlatformValidityList.dwNumEntries)
	{
		return lhs.PlatformValidityList.dwNumEntries < rhs.PlatformValidityList.dwNumEntries ? -1 : 1;
	}
	if (!lhs.PlatformValidityList.pPlatforms && !rhs.PlatformValidityList.pPlatforms)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.PlatformValidityList.pPlatforms && rhs.PlatformValidityList.pPlatforms)
	{
		for (DWORD i = 0; i < lhs.PlatformValidityList.dwNumEntries; ++i)
		{
			const auto& lhsPlatform = lhs.PlatformValidityList.pPlatforms[i];
			const auto& rhsPlatform = rhs.PlatformValidityList.pPlatforms[i];
			if (lhsPlatform.bMajorVersion != rhsPlatform.bMajorVersion)
			{
				return lhsPlatform.bMajorVersion < rhsPlatform.bMajorVersion ? -1 : 1;
			}
			if (lhsPlatform.bMinorVersion != rhsPlatform.bMinorVersion)
			{
				return lhsPlatform.bMinorVersion < rhsPlatform.bMinorVersion ? -1 : 1;
			}
			if (lhsPlatform.bPlatform != rhsPlatform.bPlatform)
			{
				return lhsPlatform.bPlatform < rhsPlatform.bPlatform ? -1 : 1;
			}
			if (lhsPlatform.Reserved != rhsPlatform.Reserved)
			{
				return lhsPlatform.Reserved < rhsPlatform.Reserved ? -1 : 1;
			}
		}
	}

	if (lhs.Status != rhs.Status)
	{
		return lhs.Status < rhs.Status ? -1 : 1;
	}

	if (lhs.Origin != rhs.Origin)
	{
		return lhs.Origin < rhs.Origin ? -1 : 1;
	}

	if (!lhs.pMetaData && !rhs.pMetaData)
	{
		// both are null, considered equal, continue comparison
	}
	else if (lhs.pMetaData && rhs.pMetaData)
	{
		if (lhs.pMetaData->qwFilterContextID != rhs.pMetaData->qwFilterContextID)
		{
			return lhs.pMetaData->qwFilterContextID < rhs.pMetaData->qwFilterContextID ? -1 : 1;
		}

		if (lhs.pMetaData->dwNumEntries != rhs.pMetaData->dwNumEntries)
		{
			return lhs.pMetaData->dwNumEntries < rhs.pMetaData->dwNumEntries ? -1 : 1;
		}

		if (!lhs.pMetaData->pEnforcementStates && !rhs.pMetaData->pEnforcementStates)
		{
			// skip the comparison
		}
		else if (lhs.pMetaData->pEnforcementStates && rhs.pMetaData->pEnforcementStates)
		{
			int metadata_comparison = memcmp(lhs.pMetaData->pEnforcementStates, rhs.pMetaData->pEnforcementStates, lhs.pMetaData->dwNumEntries * sizeof(FW_ENFORCEMENT_STATE));
			if (metadata_comparison != 0)
			{
				return metadata_comparison < 0 ? -1 : 1;
			}
		}
		else // one is null and the other is not
		{
			return lhs.pMetaData->pEnforcementStates ? 1 : -1;
		}
	}
	else // one is null and the other is not
	{
		return lhs.pMetaData ? 1 : -1;
	}

	if (lhs.dwTrustTupleKeywords != rhs.dwTrustTupleKeywords)
	{
		return lhs.dwTrustTupleKeywords < rhs.dwTrustTupleKeywords ? -1 : 1;
	}

	if (lhs.wFlags2 != rhs.wFlags2)
	{
		return lhs.wFlags2 < rhs.wFlags2 ? -1 : 1;
	}

	if (lhs.compartmentId != rhs.compartmentId)
	{
		return lhs.compartmentId < rhs.compartmentId ? -1 : 1;
	}

	const auto provider_context_key_cmp = memcmp(&lhs.providerContextKey, &rhs.providerContextKey, sizeof(lhs.providerContextKey));
	if (provider_context_key_cmp != 0)
	{
		return provider_context_key_cmp;
	}

	if (lhs.RemoteDynamicKeywordAddresses.dwNumIds != rhs.RemoteDynamicKeywordAddresses.dwNumIds)
	{
		return lhs.RemoteDynamicKeywordAddresses.dwNumIds < rhs.RemoteDynamicKeywordAddresses.dwNumIds ? -1 : 1;
	}
	if (lhs.RemoteDynamicKeywordAddresses.dwNumIds > 0)
	{
		for (DWORD entry = 0; entry < lhs.RemoteDynamicKeywordAddresses.dwNumIds; ++entry)
		{
			const auto& lhsId = lhs.RemoteDynamicKeywordAddresses.ids[entry];
			const auto& rhsId = rhs.RemoteDynamicKeywordAddresses.ids[entry];
			const auto cmp = memcmp(&lhsId, &rhsId, sizeof(lhsId));
			if (cmp != 0)
			{
				return cmp;
			}
		}
	}

	// string comparisons are pushed to the end since they are more expensive
	auto string_comparison = NormalizedString::StringCompare(lhs.wszLocalApplication, rhs.wszLocalApplication);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszLocalService, rhs.wszLocalService);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszRemoteMachineAuthorizationList, rhs.wszRemoteMachineAuthorizationList);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszRemoteUserAuthorizationList, rhs.wszRemoteUserAuthorizationList);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszEmbeddedContext, rhs.wszEmbeddedContext);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszGPOName, rhs.wszGPOName);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszLocalUserAuthorizationList, rhs.wszLocalUserAuthorizationList);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszPackageId, rhs.wszPackageId);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszLocalUserOwner, rhs.wszLocalUserOwner);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	if (lhs.OnNetworkNames.dwNumEntries != rhs.OnNetworkNames.dwNumEntries)
	{
		return lhs.OnNetworkNames.dwNumEntries < rhs.OnNetworkNames.dwNumEntries ? -1 : 1;
	}
	if (lhs.OnNetworkNames.dwNumEntries > 0)
	{
		for (DWORD entry = 0; entry < lhs.OnNetworkNames.dwNumEntries; ++entry)
		{
			string_comparison = NormalizedString::StringCompare(lhs.OnNetworkNames.wszNames[entry], rhs.OnNetworkNames.wszNames[entry]);
			if (string_comparison != 0)
			{
				return string_comparison;
			}
		}
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszSecurityRealmId, rhs.wszSecurityRealmId);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	if (lhs.RemoteOutServerNames.dwNumEntries != rhs.RemoteOutServerNames.dwNumEntries)
	{
		return lhs.RemoteOutServerNames.dwNumEntries < rhs.RemoteOutServerNames.dwNumEntries ? -1 : 1;
	}
	if (lhs.RemoteOutServerNames.dwNumEntries > 0)
	{
		for (DWORD entry = 0; entry < lhs.RemoteOutServerNames.dwNumEntries; ++entry)
		{
			string_comparison = NormalizedString::StringCompare(lhs.RemoteOutServerNames.wszNames[entry], rhs.RemoteOutServerNames.wszNames[entry]);
			if (string_comparison != 0)
			{
				return string_comparison;
			}
		}
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszFqbn, rhs.wszFqbn);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	string_comparison = NormalizedString::StringCompare(lhs.wszPackageFamilyName, rhs.wszPackageFamilyName);
	if (string_comparison != 0)
	{
		return string_comparison;
	}

	// everything matched!
	return 0;
}
