// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ApplicationAnalysis.h"
#include "NormalizedFirewallRule.h"
#include "FwDiagnose.h"

#include <cstdio>
#include <format>

namespace
{
ApplicationRuleFinding
MakeFinding(const NormalizedFirewallRule& rule, ApplicationFindingReason reason)
{
	return {
	    rule.fw_rule->wszRuleId,
	    rule.fw_rule->wszName,
	    rule.fw_rule->wszLocalApplication,
	    reason,
	    rule.local_application_lookup_error,
	    rule.rule_name.value.c_str(),
	    rule.local_application_failure_string.c_str()};
}

std::wstring
Widen(PCSTR text)
{
	// failure text is ASCII
	return std::wstring(text, text + strlen(text));
}
} // namespace

ApplicationAnalysis
AnalyzeApplicationRules(const std::vector<NormalizedFirewallRule>& rules, ApplicationFileCheck fileCheck)
{
	ApplicationAnalysis analysis;
	analysis.fileCheck = fileCheck;
	for (const auto& rule : rules)
	{
		if (!rule.fw_rule->wszLocalApplication)
		{
			continue;
		}

		++analysis.applicationRuleCount;
		if (rule.local_application_uses_service_profile_variable)
		{
			analysis.serviceProfileVariableRules.push_back(
			    MakeFinding(rule, ApplicationFindingReason::ServiceProfileEnvironmentVariable));
		}

		if (rule.local_application_exists.has_value() && !rule.local_application_exists.value())
		{
			if (rule.local_application_uses_per_user_variable)
			{
				++analysis.perUserVariableRuleCount;
			}
			analysis.missingApplicationRules.push_back(MakeFinding(
			    rule,
			    rule.local_application_uses_per_user_variable ? ApplicationFindingReason::PerUserEnvironmentVariable
			                                                  : ApplicationFindingReason::FileLookupFailed));
		}
	}
	return analysis;
}

std::wstring
PrintApplicationAnalysis(const ApplicationAnalysis& analysis, AnalysisOutput output)
{
	const bool verbose = output == AnalysisOutput::Verbose;
	std::wstring text;
	if (analysis.fileCheck == ApplicationFileCheck::SkippedWow64Redirection)
	{
		text += L"  * Skipping the check for missing application files: this 32-bit build cannot see the same paths "
		        L"as the Firewall on 64-bit Windows - use the 64-bit build\n";
	}

	if (!verbose && analysis.missingApplicationRules.empty() && analysis.serviceProfileVariableRules.empty())
	{
		return text;
	}

	text += L"  * Summary of application analysis of firewall rules:\n";
	text += std::format(L"   - count of rules with an application exe: {}\n", analysis.applicationRuleCount);
	text += std::format(
	    L"   - count of rules with an application exe referencing non-existing file: {}\n",
	    analysis.missingApplicationRules.size());
	if (verbose || analysis.perUserVariableRuleCount > 0)
	{
		text += std::format(
		    L"     - of those, using a per-user environment variable (the Firewall service resolves it as "
		    L"LocalService): {}\n",
		    analysis.perUserVariableRuleCount);
	}

	if (!analysis.serviceProfileVariableRules.empty())
	{
		text += std::format(
		    L"   - WARNING: count of rules with an application exe using %USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, "
		    L"%TEMP%, or %TMP% (resolves within the profile of the Firewall service account): {}\n",
		    analysis.serviceProfileVariableRules.size());
		for (const auto& finding : analysis.serviceProfileVariableRules)
		{
			text += std::format(
			    L"     WARNING: Application-exe:  '{}'  {}\n",
			    FirewallRuleTextToString(finding.application),
			    RuleConsoleLabel(finding.displayName, finding.ruleId));
		}
	}

	if (verbose && !analysis.missingApplicationRules.empty())
	{
		text += L"   - rules with an application exe referencing non-existing file:\n";
		for (const auto& finding : analysis.missingApplicationRules)
		{
			text += std::format(
			    L"     Application-exe:  '{}'{}  ({}) {}\n",
			    FirewallRuleTextToString(finding.application),
			    finding.reason == ApplicationFindingReason::PerUserEnvironmentVariable ? PerUserVariableNote : L"",
			    Widen(finding.failureText),
			    RuleConsoleLabel(finding.displayName, finding.ruleId));
		}
	}
	return text;
}

//
// DeleteMissingAppRules
//
// Asks, for each rule whose application file was checked and not found, whether to delete it, and
// deletes it. Each failure is printed and passed to RecordOperationFailure.
//
// Parameters:
//   rules      [in, out] - the store's rules, after the missing-application check; each rule deleted is marked
//                          is_rule_deleted, and rules already marked are skipped
//   input      [in] - where the answers are read from: std::wcin, or a scripted stream in tests. When it
//                     ends, the answer counts as 's', so nothing more is deleted without an answer.
//   deleteRule [in] - deletes one rule by rule ID; FWDeleteFirewallRule on the store's handle, or a
//                     fake in tests
//
void
DeleteMissingAppRules(
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

		if (!rule.local_application_exists.has_value())
		{
			// this rule was not checked for app file existence, skip it
			continue;
		}

		if (rule.local_application_exists.value() == true)
		{
			continue; // verified this file exists
		}

		if (!printed_deletion_header)
		{
			printed_deletion_header = true;
			PrintDeletionHeader(
			    "Deleting rules with an application exe referencing non-existing file",
			    "the one rule prompted",
			    "rules with an application exe referencing non-existing file");
		}

		std::printf(
		    "\n"
		    "     Application-exe:  '%ls'%ls  [%ls:  %ls]\n",
		    rule.fw_rule->wszLocalApplication,
		    rule.local_application_uses_per_user_variable ? PerUserVariableNote : L"",
		    rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
		    rule.rule_name.value.empty() ? rule.rule_id.c_str() : rule.rule_name.value.c_str());

		if (!delete_all_with_no_more_prompts)
		{
			switch (PromptForDeletion(RuleDeletionPrompt, input))
			{
			case PromptResponse::Yes:
				// continue to delete this rule
				break;

			case PromptResponse::No:
				std::printf("       - Skipping this rule\n");
				continue;

			case PromptResponse::Skip:
				std::printf(
				    "       - Skipping the remainder of the rules with an application exe referencing "
				    "non-existing file in this store\n");
				return;

			case PromptResponse::All:
				std::printf(
				    "       - Deleting all rules with an application exe referencing non-existing file in this "
				    "store\n");
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
