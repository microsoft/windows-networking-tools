// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <istream>
#include <string>
#include <vector>
#include <Windows.h>

#include "AnalysisOutput.h"
#include "RuleDeletion.h"
#include "RulePackageIdentity.h"

struct NormalizedFirewallRule;

inline constexpr PCWSTR PerUserVariableNote = L" (per-user environment variable)";

enum class ApplicationFileCheck : uint8_t
{
	Completed,
	// a 32-bit build on 64-bit Windows cannot look up the paths the Firewall service sees
	SkippedWow64Redirection
};

enum class ApplicationFindingReason : uint8_t
{
	PerUserEnvironmentVariable,
	FileLookupFailed,
	ServiceProfileEnvironmentVariable,
	// the file was not checked: the environment variables in its path could not be expanded
	EnvironmentExpansionFailed
};

// one rule from the application analysis; the pointers refer to the analyzed rules, which must outlive the analysis
struct ApplicationRuleFinding
{
	PCWSTR ruleId{};
	// the name as stored in the rule, for JSON
	PCWSTR name{};
	PCWSTR application{};
	ApplicationFindingReason reason{};
	HRESULT error{};
	// the name with string resources resolved, for the console; empty when the rule has no name
	PCWSTR displayName{L""};
	PCSTR failureText{""};
	// copied, because the rules are reordered before some findings are written
	std::optional<RulePackageIdentity> packageIdentity;
};

struct ApplicationAnalysis
{
	ApplicationFileCheck fileCheck{ApplicationFileCheck::Completed};
	size_t applicationRuleCount{};
	size_t perUserVariableRuleCount{};
	std::vector<ApplicationRuleFinding> missingApplicationRules;
	std::vector<ApplicationRuleFinding> serviceProfileVariableRules;
	// rules whose file could not be checked; they are not counted as missing
	std::vector<ApplicationRuleFinding> uncheckedApplicationRules;
};

ApplicationAnalysis
AnalyzeApplicationRules(const std::vector<NormalizedFirewallRule>& rules, ApplicationFileCheck fileCheck);

// the console text for one store's application analysis; empty when there is nothing to report
std::wstring
PrintApplicationAnalysis(const ApplicationAnalysis& analysis, AnalysisOutput output);

void
DeleteMissingAppRules(
    std::vector<NormalizedFirewallRule>& rules,
    std::wistream& input,
    const DeleteFirewallRuleFunction& deleteRule,
    StoreCleanup& cleanup);
