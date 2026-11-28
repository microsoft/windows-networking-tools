// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <format>
#include <string>
#include <Windows.h>

#include "NormalizedFirewallRule.h"

// how much an analysis prints to the console
enum class AnalysisOutput : uint8_t
{
	Summary,
	Verbose
};

// "[Rule Name:  name]", or "[(no Rule Name) RuleId:  id]" when the rule has no name
inline std::wstring
RuleConsoleLabel(PCWSTR displayName, PCWSTR ruleId)
{
	const bool hasName = displayName && displayName[0] != L'\0';
	return std::format(
	    L"[{}:  {}]",
	    hasName ? L"Rule Name" : L"(no Rule Name) RuleId",
	    hasName ? std::wstring{displayName} : FirewallRuleTextToString(ruleId));
}
