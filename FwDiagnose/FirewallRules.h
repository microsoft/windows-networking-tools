// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <vector>
#include <string>
#include <tuple>
#include "NormalizedFirewallRule.h"

struct FirewallPolicyObjects
{
	FW_RULE* parent_rule{};

	std::vector<NormalizedFirewallRule> normalizedRules;

	PCSTR store_type_string{};
	FW_STORE_TYPE store_type{};
	HRESULT load_result{E_PENDING};

	// remains open until the process exits - -clean-rules deletes rules through it
	FW_POLICY_STORE_HANDLE store_handle{};
};

HRESULT
LoadFirewallRules() noexcept;
HRESULT
AnalyzeFirewallRulesReferencingAppPackages();

std::vector<std::tuple<std::string, FW_RULE*, WORD>>
GetRulesWithAppPackages();

bool
HasFirewallAdminAccess();

void
ProcessFirewallPolicy(PCWSTR command = L"analyze_rules") noexcept;
void
ProcessFirewallRules();
void
ProcessInboundRules();
void
ProcessShieldsUp() noexcept;
