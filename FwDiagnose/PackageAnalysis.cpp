// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "PackageAnalysis.h"
#include "NormalizedFirewallRule.h"

#include <format>

PackageAnalysis
AnalyzePackageRules(
    std::vector<NormalizedFirewallRule>& rules, HRESULT packagesLoadResult, const PackageLookups& lookups)
{
	PackageAnalysis analysis;
	analysis.packagesLoadResult = packagesLoadResult;
	// without the list of installed packages, every package would look like it does not exist
	if (FAILED(packagesLoadResult))
	{
		return analysis;
	}

	for (auto& rule : rules)
	{
		const PCWSTR package_id = rule.fw_rule->wszPackageId; // the package ID SID
		if (package_id && package_id[0] != L'\0')
		{
			++analysis.packageIdRuleCount;
			if (!lookups.packageIdExists(package_id))
			{
				rule.missing_package_id = true;
				analysis.missingPackageRules.push_back(
				    {rule.fw_rule->wszRuleId,
				     rule.fw_rule->wszName,
				     PackageReference::PackageId,
				     package_id,
				     rule.rule_name.value.c_str()});
			}
		}

		// PackageFamilyName() is nullptr unless both the requested version and the rule's schema version support it
		const PCWSTR package_family_name = rule.PackageFamilyName();
		if (package_family_name && package_family_name[0] != L'\0')
		{
			++analysis.packageFamilyNameRuleCount;
			if (!lookups.packageFamilyNameExists(rule.normalized_package_family_name))
			{
				rule.missing_package_family_name = true;
				analysis.missingPackageRules.push_back(
				    {rule.fw_rule->wszRuleId,
				     rule.fw_rule->wszName,
				     PackageReference::PackageFamilyName,
				     package_family_name,
				     rule.rule_name.value.c_str()});
			}
		}
	}
	return analysis;
}

std::wstring
PrintPackageAnalysis(const PackageAnalysis& analysis, AnalysisOutput output)
{
	if (FAILED(analysis.packagesLoadResult))
	{
		return std::format(
		    L"  * Skipping the app-package analysis: installed packages could not be loaded (0x{:08X})\n",
		    static_cast<uint32_t>(analysis.packagesLoadResult));
	}

	std::wstring text = L"  * Summary of app-package analysis of firewall rules:\n";
	text += std::format(L"   - count of rules with a package ID: {}\n", analysis.packageIdRuleCount);
	text += std::format(
	    L"   - count of rules with a package ID referencing a non-existing package: {}\n",
	    analysis.MissingCount(PackageReference::PackageId));
	text += std::format(L"   - count of rules with a package family name: {}\n", analysis.packageFamilyNameRuleCount);
	text += std::format(
	    L"   - count of rules with a package family name referencing a non-existing package: {}\n",
	    analysis.MissingCount(PackageReference::PackageFamilyName));

	if (output == AnalysisOutput::Verbose && !analysis.missingPackageRules.empty())
	{
		text += L"   - rules referencing a non-existing package:\n";
		for (const auto& finding : analysis.missingPackageRules)
		{
			text += std::format(
			    L"     {}:  '{}'  {}\n",
			    finding.reference == PackageReference::PackageId ? L"Package-ID" : L"Package-Family-Name",
			    FirewallRuleTextToString(finding.package),
			    RuleConsoleLabel(finding.displayName, finding.ruleId));
		}
	}
	return text;
}
