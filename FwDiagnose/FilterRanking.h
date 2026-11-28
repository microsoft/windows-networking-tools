// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <functional>
#include <string>
#include <vector>
#include <Windows.h>

#include "AnalysisOutput.h"

// the WFP filters whose display name matches a rule name; filters from every store share one count
struct FilterCounts
{
	size_t filterCount{};
	size_t filterConditionCount{};
};

// rules are linked to WFP filters only by display name, so rules sharing a name are ranked together
struct RankedRuleName
{
	// the normalized (lowercase) name used to match filters
	std::wstring ruleName;
	size_t ruleCount{};
	size_t filterCount{};
	size_t filterConditionCount{};
	// in rule order; the pointers refer to the analyzed rules, which must outlive the rankings
	std::vector<PCWSTR> ruleIds;
};

struct FilterRankings
{
	// a failure means the WFP filters could not be read, so nothing was ranked
	HRESULT filtersLoadResult{S_OK};
	// the most rule names each ranking holds
	size_t limit{};
	// highest count first, then by name; rule names without filters or conditions are not ranked
	std::vector<RankedRuleName> byFilterCount;
	std::vector<RankedRuleName> byFilterConditionCount;
};

using FilterCounter = std::function<FilterCounts(const NormalizedString& ruleName)>;

// the limit is 10 for verbose output and 3 otherwise
FilterRankings
AnalyzeFilterRankings(
    const std::vector<NormalizedFirewallRule>& rules,
    HRESULT filtersLoadResult,
    AnalysisOutput output,
    const FilterCounter& countFilters);

// the console text for one store's rankings; empty when there is nothing to report
std::wstring
PrintFilterRankings(const FilterRankings& rankings);
