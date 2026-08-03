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

	std::optional<bool> local_application_exists{ std::nullopt };

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

	bool RuleTargetsLocalUser() const;
	bool RuleTargetsNtService() const;
	bool RuleTargetsLocalNonSystemApplication() const;
	bool RuleTargetsLocalSystemApplication() const;
	bool RuleTargetsLocalAppxRuleApplication() const;

private:
	void CheckIfLocalApplicationExists();
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

enum ComparisonPolicy : uint8_t
{
	comparison_policy_all = 0x0,
	comparison_policy_skip_comparing_profiles = 0x1,
	comparison_policy_skip_comparing_if_enabled = 0x2,
	comparison_policy_skip_comparing_local_subnet = 0x4,
};
DEFINE_ENUM_FLAG_OPERATORS(ComparisonPolicy)

// returns the same integer value as memcmp()
// -1 if lhs < rhs, 0 if equal, +1 if lhs > rhs
inline int RuleDetailsComparison(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs, ComparisonPolicy policy = comparison_policy_all) noexcept
{
	// check the optional fields based off the bool input parameters
	if (policy & comparison_policy_skip_comparing_profiles)
	{
		// don't compare dwProfiles
	}
	else if (lhs.fw_rule->dwProfiles != rhs.fw_rule->dwProfiles)
	{
		return lhs.fw_rule->dwProfiles < rhs.fw_rule->dwProfiles ? -1 : 1;
	}

	if (policy & comparison_policy_skip_comparing_if_enabled)
	{
		// don't match if the rules are enabled
		// remove the FW_RULE_FLAGS_ACTIVE flag from both before comparing
		const auto lhs_flags = lhs.fw_rule->wFlags & ~FW_RULE_FLAGS_ACTIVE;
		const auto rhs_flags = rhs.fw_rule->wFlags & ~FW_RULE_FLAGS_ACTIVE;
		if (lhs_flags != rhs_flags)
		{
			return lhs_flags < rhs_flags ? -1 : 1;
		}
	}
	else
	{
		if (lhs.fw_rule->wFlags != rhs.fw_rule->wFlags)
		{
			return lhs.fw_rule->wFlags < rhs.fw_rule->wFlags ? -1 : 1;
		}
	}

	if (policy & comparison_policy_skip_comparing_local_subnet)
	{
		// not comparing local subnets
		// remove the FW_ADDRESS_KEYWORD_LOCAL_SUBNET flag from both before comparing

		const auto lhs_local_v4_keywords = lhs.fw_rule->LocalAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_local_v4_keywords = rhs.fw_rule->LocalAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if ((lhs_local_v4_keywords == rhs_local_v4_keywords) && (lhs.fw_rule->LocalAddresses.dwV4AddressKeywords != rhs.fw_rule->LocalAddresses.dwV4AddressKeywords))
		{
			std::printf("** Local IPv4 subnet keyword mismatch only with FW_ADDRESS_KEYWORD_LOCAL_SUBNET, but ignoring due to comparison policy.\n");
		}
		if (lhs_local_v4_keywords != rhs_local_v4_keywords)
		{
			return lhs_local_v4_keywords < rhs_local_v4_keywords ? -1 : 1;
		}

		const auto lhs_local_v6_keywords = lhs.fw_rule->LocalAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_local_v6_keywords = rhs.fw_rule->LocalAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if ((lhs_local_v6_keywords == rhs_local_v6_keywords) && (lhs.fw_rule->LocalAddresses.dwV6AddressKeywords != rhs.fw_rule->LocalAddresses.dwV6AddressKeywords))
		{
			std::printf("** Local IPv6 subnet keyword mismatch only with FW_ADDRESS_KEYWORD_LOCAL_SUBNET, but ignoring due to comparison policy.\n");
		}
		if (lhs_local_v6_keywords != rhs_local_v6_keywords)
		{
			return lhs_local_v6_keywords < rhs_local_v6_keywords ? -1 : 1;
		}

		const auto lhs_remote_v4_keywords = lhs.fw_rule->RemoteAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_remote_v4_keywords = rhs.fw_rule->RemoteAddresses.dwV4AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if ((lhs_remote_v4_keywords == rhs_remote_v4_keywords) && (lhs.fw_rule->RemoteAddresses.dwV4AddressKeywords != rhs.fw_rule->RemoteAddresses.dwV4AddressKeywords))
		{
			std::printf("** Remote IPv4 subnet keyword mismatch only with FW_ADDRESS_KEYWORD_LOCAL_SUBNET, but ignoring due to comparison policy.\n");
		}
		if (lhs_remote_v4_keywords != rhs_remote_v4_keywords)
		{
			return lhs_remote_v4_keywords < rhs_remote_v4_keywords ? -1 : 1;
		}

		const auto lhs_remote_v6_keywords = lhs.fw_rule->RemoteAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		const auto rhs_remote_v6_keywords = rhs.fw_rule->RemoteAddresses.dwV6AddressKeywords & ~FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
		if ((lhs_remote_v6_keywords == rhs_remote_v6_keywords) && (lhs.fw_rule->RemoteAddresses.dwV6AddressKeywords != rhs.fw_rule->RemoteAddresses.dwV6AddressKeywords))
		{
			std::printf("** Remote IPv6 subnet keyword mismatch only with FW_ADDRESS_KEYWORD_LOCAL_SUBNET, but ignoring due to comparison policy.\n");
		}
		if (lhs_remote_v6_keywords != rhs_remote_v6_keywords)
		{
			return lhs_remote_v6_keywords < rhs_remote_v6_keywords ? -1 : 1;
		}
	}
	else
	{
		if (lhs.fw_rule->LocalAddresses.dwV4AddressKeywords != rhs.fw_rule->LocalAddresses.dwV4AddressKeywords)
		{
			return lhs.fw_rule->LocalAddresses.dwV4AddressKeywords < rhs.fw_rule->LocalAddresses.dwV4AddressKeywords ? -1 : 1;
		}
		if (lhs.fw_rule->LocalAddresses.dwV6AddressKeywords != rhs.fw_rule->LocalAddresses.dwV6AddressKeywords)
		{
			return lhs.fw_rule->LocalAddresses.dwV6AddressKeywords < rhs.fw_rule->LocalAddresses.dwV6AddressKeywords ? -1 : 1;
		}
		if (lhs.fw_rule->RemoteAddresses.dwV4AddressKeywords != rhs.fw_rule->RemoteAddresses.dwV4AddressKeywords)
		{
			return lhs.fw_rule->RemoteAddresses.dwV4AddressKeywords < rhs.fw_rule->RemoteAddresses.dwV4AddressKeywords ? -1 : 1;
		}
		if (lhs.fw_rule->RemoteAddresses.dwV6AddressKeywords != rhs.fw_rule->RemoteAddresses.dwV6AddressKeywords)
		{
			return lhs.fw_rule->RemoteAddresses.dwV6AddressKeywords < rhs.fw_rule->RemoteAddresses.dwV6AddressKeywords ? -1 : 1;
		}
	}

	return NormalizedString::StringCompare(lhs.normalized_rule_details, rhs.normalized_rule_details);
}
