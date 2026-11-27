// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ApplicationAnalysis.h"
#include "NormalizedFirewallRule.h"

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
