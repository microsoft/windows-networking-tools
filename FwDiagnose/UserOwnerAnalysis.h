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

// whether rule owners were checked against the local profiles in the registry
enum class LocalProfileCheck : uint8_t
{
	// only Application-Isolation and Interface-Isolation rules are recreated for each local profile
	NotApplicable,
	Completed,
	// the profile list could not be read, so no rule was checked
	Failed
};

struct LocalProfiles
{
	LocalProfileCheck check{LocalProfileCheck::NotApplicable};
	HRESULT readResult{S_OK};
	// profile SIDs that resolve to an account
	std::vector<std::wstring> sids;
};

// the pointers refer to the analyzed rules, which must outlive the analysis
struct UnresolvedSidFinding
{
	PCWSTR ruleId{};
	// the name as stored in the rule, for JSON
	PCWSTR name{};
	PCWSTR localUserOwnerSid{};
	UserOwnerResolveFailure reason{UserOwnerResolveFailure::None};
	HRESULT error{S_OK};
	// the name with string resources resolved, for the console; empty when the rule has no name
	PCWSTR displayName{L""};
	// ASCII
	PCSTR failureText{""};
};

struct MissingLocalProfileFinding
{
	PCWSTR ruleId{};
	PCWSTR name{};
	PCWSTR localUserOwnerSid{};
	PCWSTR domain{L""};
	PCWSTR user{L""};
	PCWSTR displayName{L""};
};

struct UserOwnerAnalysis
{
	LocalProfileCheck localProfileCheck{LocalProfileCheck::NotApplicable};
	HRESULT localProfilesReadResult{S_OK};
	size_t localUserOwnerRuleCount{};
	std::vector<UnresolvedSidFinding> unresolvedSidRules;
	// empty unless localProfileCheck is Completed
	std::vector<MissingLocalProfileFinding> missingLocalProfileRules;
};

// sets unresolve_user_sid and successfully_resolved_user_name_with_local_profile on the analyzed rules
UserOwnerAnalysis
AnalyzeUserOwnerRules(std::vector<NormalizedFirewallRule>& rules, const LocalProfiles& localProfiles);

// the console text for one store's SID-owner analysis; empty when there is nothing to report
std::wstring
PrintUserOwnerAnalysis(const UserOwnerAnalysis& analysis, AnalysisOutput output);

void
DeleteUnresolvedUserAccountRules(
    std::vector<NormalizedFirewallRule>& rules, std::wistream& input, const DeleteFirewallRuleFunction& deleteRule);
