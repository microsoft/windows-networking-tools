// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <vector>
#include "NormalizedFirewallRule.h"

struct DuplicateRuleDetails
{
	const std::vector<NormalizedFirewallRule>::iterator duplicate_rule_begin;
	const std::vector<NormalizedFirewallRule>::iterator duplicate_rule_end;
};

struct FirewallPolicyObjects
{
	FW_RULE* parent_rule{};
	PCSTR type_string{};
	FW_STORE_TYPE type{};
	std::vector<NormalizedFirewallRule> normalizedRules;
};

HRESULT LoadFirewallRules() noexcept;
std::vector<std::tuple<std::string, FW_RULE*>> GetRulesWithAppPackages();

bool HasFirewallAdminAccess();

void ProcessFirewallRules();
