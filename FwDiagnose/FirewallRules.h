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

	std::vector<NormalizedFirewallRule> normalizedRules;

	PCSTR store_type_string{};
	FW_STORE_TYPE store_type{};
	WORD rule_version{};
};

HRESULT LoadFirewallRules() noexcept;
HRESULT AnalyzeFirewallRulesReferencingAppPackages();

std::vector<std::tuple<std::string, FW_RULE*, WORD>> GetRulesWithAppPackages();

bool HasFirewallAdminAccess();

void ProcessFirewallPolicy() noexcept;
void ProcessFirewallRules();
void ProcessInboundPublicRules();
void ProcessPrivateOnlyInboundRules();
void ProcessInboundRules();
void ProcessShieldsUp() noexcept;
