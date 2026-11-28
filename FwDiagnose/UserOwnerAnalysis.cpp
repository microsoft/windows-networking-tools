// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "UserOwnerAnalysis.h"
#include "NormalizedFirewallRule.h"
#include "FwDiagnose.h"
#include <algorithm>
#include <cstdio>
#include <format>
#include <wil/stl.h>
#include <wil/resource.h>

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

//
// DeleteUnresolvedUserAccountRules
//
// Asks, for each rule whose owner SID does not resolve to an account, or (in the Application-Isolation
// and Interface-Isolation stores) resolves but has no local profile, whether to delete it, and deletes
// it. Each failure is printed and passed to RecordOperationFailure.
//
// Parameters:
//   rules      [in, out] - the store's rules, after AnalyzeUserOwnerRules; each rule deleted is marked
//                          is_rule_deleted, and rules already marked are skipped
//   input      [in] - where the answers are read from: std::wcin, or a scripted stream in tests. When it
//                     ends, the answer counts as 's', so nothing more is deleted without an answer.
//   deleteRule [in] - deletes one rule by rule ID; FWDeleteFirewallRule on the store's handle, or a
//                     fake in tests
//
void
DeleteUnresolvedUserAccountRules(
    std::vector<NormalizedFirewallRule>& rules, std::wistream& input, const DeleteFirewallRuleFunction& deleteRule)
{
	bool delete_all_with_no_more_prompts = false;
	bool printed_deletion_header = false;

	for (auto& rule : rules)
	{
		if (rule.is_rule_deleted)
		{
			continue;
		}

		if (!rule.successfully_resolved_user_name.has_value())
		{
			// this rule was not checked for user account existence, skip it
			continue;
		}

		// prompt to delete if:
		// - rule does not have a valid user account
		// - rule has a valid user account but does not have a local profile (only for App-Isolation and Interface-Isolation stores)
		std::wstring rule_to_delete;
		if (!rule.successfully_resolved_user_name.value())
		{
			rule_to_delete = wil::str_printf<std::wstring>(
			    L"\n"
			    L"  - Unresolved SID '%ls'  (%hs)  [%ls:  %ls]\n",
			    rule.fw_rule->wszLocalUserOwner,
			    rule.resolve_name_failure_string.c_str(),
			    rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			    rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str());
		}

		if (rule.successfully_resolved_user_name_with_local_profile.has_value())
		{
			// name resolved - only prompt if checking for local profile and rule does not have a local profile
			if (!rule.successfully_resolved_user_name_with_local_profile.value())
			{
				rule_to_delete = wil::str_printf<std::wstring>(
				    L"\n"
				    L"  - Valid SID but no local profile '%ls' (%ls\\%ls)\n"
				    L"      [%ls:  %ls]\n",
				    rule.fw_rule->wszLocalUserOwner,
				    rule.local_user_domain_name.c_str(),
				    rule.local_user_owner_name.c_str(),
				    rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
				    rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str());
			}
		}

		if (rule_to_delete.empty())
		{
			continue;
		}

		if (!printed_deletion_header)
		{
			printed_deletion_header = true;
			PrintDeletionHeader("Deleting rules with unresolved SIDs or SIDs without local profiles:\n");
		}

		std::printf("%ls", rule_to_delete.c_str());

		if (!delete_all_with_no_more_prompts)
		{
			switch (PromptForDeletion(DeletionPrompt, input))
			{
			case PromptResponse::Yes:
				// continue to delete this rule
				break;

			case PromptResponse::No:
				std::printf("       - Skipping this rule\n");
				continue;

			case PromptResponse::Skip:
				std::printf("       -Skipping the remainder of the rules with unresolved SIDs in this store\n");
				return;

			case PromptResponse::All:
				std::printf("       - Deleting all rules with unresolved SIDs in this store\n");
				delete_all_with_no_more_prompts = true;
				break;
			}
		}

		const auto deleteRuleError = deleteRule(rule.fw_rule->wszRuleId);
		if (deleteRuleError != ERROR_SUCCESS)
		{
			std::printf("       - Failed to delete the firewall rule (0x%lx)\n", HRESULT_FROM_WIN32(deleteRuleError));
			RecordOperationFailure(HRESULT_FROM_WIN32(deleteRuleError));
		}
		else
		{
			rule.is_rule_deleted = true;
			std::printf("       - Successfully deleted the firewall rule\n");
		}
	}
}
