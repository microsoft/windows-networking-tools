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
#include "RulePackageIdentity.h"

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
	// copied, because the rules are reordered before some findings are written
	std::optional<RulePackageIdentity> packageIdentity;
};

enum class PackageNameKind : uint8_t
{
	FullName,
	FamilyName
};

// an installed package whose app-container SID could not be derived. A failure from the family name means
// a rule naming that package by package ID cannot be matched to it, so it is reported as referencing a
// missing package. A failure from the full name is informational: rules use the family-name SID, and a
// full name longer than 64 characters is never a valid app-container name.
struct AppContainerSidFailure
{
	std::wstring packageName;
	PackageNameKind kind{PackageNameKind::FamilyName};
	HRESULT error{S_OK};
};

struct PackageAnalysis
{
	// a failure means the installed packages could not be loaded, so no rule was checked
	HRESULT packagesLoadResult{S_OK};
	size_t packageIdRuleCount{};
	size_t packageFamilyNameRuleCount{};
	// in rule order; a rule missing both its package ID and its package family name appears twice
	std::vector<PackageRuleFinding> missingPackageRules;
	// installed packages whose app-container SID could not be derived; empty when the packages were not loaded
	std::vector<AppContainerSidFailure> sidFailures;

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

// sets missing_package_id and missing_package_family_name on the rules whose package is not installed;
// sidFailures are the installed packages whose app-container SID could not be derived, kept only when the
// packages were loaded
PackageAnalysis
AnalyzePackageRules(
    std::vector<NormalizedFirewallRule>& rules,
    HRESULT packagesLoadResult,
    const PackageLookups& lookups,
    std::vector<AppContainerSidFailure>&& sidFailures);

std::wstring
PrintPackageAnalysis(const PackageAnalysis& analysis, AnalysisOutput output);
