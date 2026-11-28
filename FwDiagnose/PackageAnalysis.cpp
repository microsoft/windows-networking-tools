// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "PackageAnalysis.h"
#include "NormalizedFirewallRule.h"

#include <algorithm>
#include <format>
#include <utility>

PackageAnalysis
AnalyzePackageRules(
    std::vector<NormalizedFirewallRule>& rules,
    HRESULT packagesLoadResult,
    const PackageLookups& lookups,
    std::vector<AppContainerSidFailure>&& sidFailures)
{
	PackageAnalysis analysis;
	analysis.packagesLoadResult = packagesLoadResult;
	// without the list of installed packages, every package would look like it does not exist
	if (FAILED(packagesLoadResult))
	{
		return analysis;
	}

	analysis.sidFailures = std::move(sidFailures);
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
				     rule.rule_name.value.c_str(),
				     rule.package_identity});
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
				     rule.rule_name.value.c_str(),
				     rule.package_identity});
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
	const auto familyNameFailures =
	    std::ranges::count(analysis.sidFailures, PackageNameKind::FamilyName, &AppContainerSidFailure::kind);
	const auto fullNameFailures = analysis.sidFailures.size() - static_cast<size_t>(familyNameFailures);
	const auto appendFailures = [&](PackageNameKind kind)
	{
		for (const auto& failure : analysis.sidFailures)
		{
			if (failure.kind == kind)
			{
				text += std::format(
					L"     '{}'  (0x{:08X})\n",
					failure.packageName,
					static_cast<uint32_t>(failure.error));
			}
		}
	};
	if (familyNameFailures > 0)
	{
		text += std::format(
		    L"   - WARNING: count of installed packages whose app-container SID could not be derived from the family "
		    L"name (rules naming them by package ID are reported as referencing a non-existing package): {}\n",
		    familyNameFailures);
		if (output == AnalysisOutput::Verbose)
		{
			appendFailures(PackageNameKind::FamilyName);
		}
	}
	// informational only: rules use the family-name SID
	if (fullNameFailures > 0 && output == AnalysisOutput::Verbose)
	{
		text += std::format(
		    L"   - count of installed packages whose app-container SID could not be derived from the full name "
		    L"(rules use the family name, so this does not affect the analysis): {}\n",
		    fullNameFailures);
		appendFailures(PackageNameKind::FullName);
	}

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
