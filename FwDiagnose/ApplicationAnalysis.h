// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>

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
	ServiceProfileEnvironmentVariable
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
};

struct ApplicationAnalysis
{
	ApplicationFileCheck fileCheck{ApplicationFileCheck::Completed};
	size_t applicationRuleCount{};
	size_t perUserVariableRuleCount{};
	std::vector<ApplicationRuleFinding> missingApplicationRules;
	std::vector<ApplicationRuleFinding> serviceProfileVariableRules;
};

enum class ApplicationAnalysisOutput : uint8_t
{
	Summary,
	Verbose
};

ApplicationAnalysis
AnalyzeApplicationRules(const std::vector<NormalizedFirewallRule>& rules, ApplicationFileCheck fileCheck);

// the console text for one store's application analysis; empty when there is nothing to report
std::wstring
PrintApplicationAnalysis(const ApplicationAnalysis& analysis, ApplicationAnalysisOutput output);
