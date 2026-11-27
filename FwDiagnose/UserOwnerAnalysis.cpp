// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "UserOwnerAnalysis.h"
#include "NormalizedFirewallRule.h"

#include <algorithm>
#include <format>

namespace
{
std::wstring
Widen(PCSTR text)
{
	// failure text is ASCII
	return std::wstring(text, text + strlen(text));
}
} // namespace

UserOwnerAnalysis
AnalyzeUserOwnerRules(std::vector<NormalizedFirewallRule>& rules, const LocalProfiles& localProfiles)
{
	UserOwnerAnalysis analysis;
	analysis.localProfileCheck = localProfiles.check;
	analysis.localProfilesReadResult = localProfiles.readResult;

	for (auto& rule : rules)
	{
		if (!rule.successfully_resolved_user_name.has_value())
		{
			continue;
		}

		++analysis.localUserOwnerRuleCount;

		if (!rule.successfully_resolved_user_name.value())
		{
			rule.unresolve_user_sid = true;
			analysis.unresolvedSidRules.push_back(
			    {rule.fw_rule->wszRuleId,
			     rule.fw_rule->wszName,
			     rule.fw_rule->wszLocalUserOwner,
			     rule.resolve_name_failure,
			     rule.resolve_name_error,
			     rule.rule_name.value.c_str(),
			     rule.resolve_name_failure_string.c_str()});
		}
		else if (localProfiles.check == LocalProfileCheck::Completed)
		{
			const PCWSTR owner = rule.fw_rule->wszLocalUserOwner;
			const bool hasLocalProfile = std::ranges::any_of(
			    localProfiles.sids,
			    [owner](const std::wstring& sid)
			    {
				    return _wcsicmp(sid.c_str(), owner) == 0;
			    });
			rule.successfully_resolved_user_name_with_local_profile = hasLocalProfile;
			if (!hasLocalProfile)
			{
				analysis.missingLocalProfileRules.push_back(
				    {rule.fw_rule->wszRuleId,
				     rule.fw_rule->wszName,
				     owner,
				     rule.local_user_domain_name.c_str(),
				     rule.local_user_owner_name.c_str(),
				     rule.rule_name.value.c_str()});
			}
		}
	}
	return analysis;
}

std::wstring
PrintUserOwnerAnalysis(const UserOwnerAnalysis& analysis, AnalysisOutput output)
{
	const bool verbose = output == AnalysisOutput::Verbose;
	std::wstring text;
	if (analysis.localProfileCheck == LocalProfileCheck::Failed)
	{
		text += std::format(
		    L"  * Skipping the local-profile check: local profiles could not be read (0x{:08X})\n",
		    static_cast<uint32_t>(analysis.localProfilesReadResult));
	}

	if (!verbose && analysis.unresolvedSidRules.empty() && analysis.missingLocalProfileRules.empty())
	{
		return text;
	}

	text += L"  * Summary of SID owner analysis of firewall rules:\n";
	text += std::format(L"   - count of rules with LocalUserOwner SID: {}\n", analysis.localUserOwnerRuleCount);
	text += std::format(
	    L"   - count of rules with LocalUserOwner SID referencing unresolved SID: {}\n",
	    analysis.unresolvedSidRules.size());
	if (analysis.localProfileCheck == LocalProfileCheck::Completed)
	{
		text += std::format(
		    L"   - count of rules with LocalUserOwner SID referencing non-existing local profile: {}\n",
		    analysis.missingLocalProfileRules.size());
	}

	if (verbose)
	{
		if (!analysis.unresolvedSidRules.empty())
		{
			text += L"   - rules with unresolved SIDs:\n";
		}
		for (const auto& finding : analysis.unresolvedSidRules)
		{
			text += std::format(
			    L"     Unresolved SID:  '{}'  ({})  {}\n",
			    FirewallRuleTextToString(finding.localUserOwnerSid),
			    Widen(finding.failureText),
			    RuleConsoleLabel(finding.displayName, finding.ruleId));
		}

		if (!analysis.missingLocalProfileRules.empty())
		{
			text += L"   - rules with no local profile:\n";
		}
		for (const auto& finding : analysis.missingLocalProfileRules)
		{
			const bool hasDomain = finding.domain && finding.domain[0] != L'\0';
			text += std::format(
			    L"     SID:  '{}' ({}{}{})  {}\n",
			    FirewallRuleTextToString(finding.localUserOwnerSid),
			    hasDomain ? finding.domain : L"",
			    hasDomain ? L"\\" : L"",
			    FirewallRuleTextToString(finding.user),
			    RuleConsoleLabel(finding.displayName, finding.ruleId));
		}
	}
	return text;
}
