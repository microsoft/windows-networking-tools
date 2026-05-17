// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <Windows.h>

#include "firewall.h"
#include "NormalizedString.h"
#include "WfpCounters.h"

#include <wil/resource.h>

struct NormalizedFirewallRule
{
	NormalizedFirewallRule(const FW_RULE* fwRule, WORD requestedRuleVersion);

	const FW_RULE* fw_rule{};
	WORD requested_rule_version{};
	std::wstring rule_id{};
	NormalizedString rule_name{ NormalizedString::Create(L"") };
	std::wstring rule_description{};

	NormalizedString normalized_rule_details{NormalizedString::Create(L"")};
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
