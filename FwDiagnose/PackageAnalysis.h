// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <Windows.h>

#include "AnalysisOutput.h"

struct NormalizedFirewallRule;

enum class PackageReference : uint8_t
{
	PackageId,
	PackageFamilyName
};

// one missing package reference; the pointers refer to the analyzed rules, which must outlive the analysis
struct PackageRuleFinding
{
	PCWSTR ruleId{};
	// the name as stored in the rule, for JSON
	PCWSTR name{};
	PackageReference reference{};
	// the package ID SID or the package family name
	PCWSTR package{};
	// the name with string resources resolved, for the console; empty when the rule has no name
	PCWSTR displayName{L""};
};

struct PackageAnalysis
{
	// a failure means the installed packages could not be loaded, so no rule was checked
	HRESULT packagesLoadResult{S_OK};
	size_t packageIdRuleCount{};
	size_t packageFamilyNameRuleCount{};
	// in rule order; a rule missing both its package ID and its package family name appears twice
	std::vector<PackageRuleFinding> missingPackageRules;

	size_t
	MissingCount(PackageReference reference) const noexcept
	{
		return static_cast<size_t>(std::ranges::count_if(
		    missingPackageRules,
		    [reference](const PackageRuleFinding& finding)
		    {
			    return finding.reference == reference;
		    }));
	}
};

// returns true when the installed packages include the reference
struct PackageLookups
{
	std::function<bool(PCWSTR packageSid)> packageIdExists;
	std::function<bool(const NormalizedString& packageFamilyName)> packageFamilyNameExists;
};

// sets missing_package_id and missing_package_family_name on the rules whose package is not installed
PackageAnalysis
AnalyzePackageRules(
    std::vector<NormalizedFirewallRule>& rules, HRESULT packagesLoadResult, const PackageLookups& lookups);

std::wstring
PrintPackageAnalysis(const PackageAnalysis& analysis, AnalysisOutput output);
