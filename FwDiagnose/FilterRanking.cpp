// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilterRanking.h"
#include "NormalizedFirewallRule.h"

#include <algorithm>
#include <format>

namespace
{
//
// TopRuleNames
//
// Ranks rule names by one of their counts and keeps the highest ones.
//
// Parameters:
//   ruleNames [in] - every rule name in the store, with both of its counts
//   limit     [in] - the most rule names to keep
//   count     [in] - which count to rank by: &RankedRuleName::filterCount or
//                    &RankedRuleName::filterConditionCount
//
// Returns:
//   Up to limit copies of the entries in ruleNames whose count is above zero, highest count
//   first; ties are ordered by rule name so the output is the same on every run.
//
// About the type of count, "size_t RankedRuleName::*":
//   This is a pointer to a data member. It does not point at a value in memory; it names one
//   size_t member of RankedRuleName, whichever struct instance it is later applied to. The
//   caller passes &RankedRuleName::filterCount (no instance), and this function reads that
//   member from any entry with "entry.*count" (or "pointer->*count" through a pointer). It lets
//   one function rank by either count without duplicating the code or passing a lambda.
//
std::vector<RankedRuleName>
TopRuleNames(const std::vector<RankedRuleName>& ruleNames, size_t limit, size_t RankedRuleName::* count)
{
	std::vector<RankedRuleName> ranked;
	for (const auto& ruleName : ruleNames)
	{
		if (ruleName.*count > 0)
		{
			ranked.push_back(ruleName);
		}
	}
	std::ranges::sort(
	    ranked,
	    [count](const RankedRuleName& lhs, const RankedRuleName& rhs)
	    {
		    if (lhs.*count != rhs.*count)
		    {
			    return lhs.*count > rhs.*count;
		    }
		    return lhs.ruleName < rhs.ruleName;
	    });
	if (ranked.size() > limit)
	{
		ranked.resize(limit);
	}
	return ranked;
}

//
// PrintRanking
//
// Appends one ranking, as console text, to text.
//
// Parameters:
//   text    [in, out] - the console text being built; the ranking is appended to it
//   heading [in]      - what the ranking is by, e.g. L"WFP filter count"
//   limit   [in]      - the most rule names the ranking could hold, shown in the heading
//   ranking [in]      - the ranked rule names, from TopRuleNames
//   count   [in]      - which count to print for each rule name (a pointer to a data member;
//                       see TopRuleNames)
//   unit    [in]      - the word printed after the count, e.g. L"filters"
//
// Appends nothing when the ranking is empty.
//
void
PrintRanking(
    std::wstring& text,
    PCWSTR heading,
    size_t limit,
    const std::vector<RankedRuleName>& ranking,
    size_t RankedRuleName::* count,
    PCWSTR unit)
{
	if (ranking.empty())
	{
		return;
	}

	text += std::format(L"\n  * Top {} rule names by {}:\n", limit, heading);
	for (const auto& ruleName : ranking)
	{
		text += std::format(
		    L"    [{} {}] '{}'",
		    ruleName.*count,
		    unit,
		    FirewallRuleTextToString(ruleName.ruleName.c_str()));
		if (ruleName.ruleCount > 1)
		{
			text += std::format(L"  [{} rules match this name]", ruleName.ruleCount);
		}
		text += L"\n";
	}
}
} // namespace

//
// AnalyzeFilterRankings
//
// Ranks the rule names in one store by how many WFP filters, and filter conditions, have the
// same display name. Rules are linked to filters only by name, so rules that share a name
// (compared case-insensitively) are ranked as one entry.
//
// Parameters:
//   rules             [in] - the store's rules, in any order; the result points at their rule IDs,
//                            so they must outlive the result
//   filtersLoadResult [in] - the result of reading the WFP filters; when it is a failure nothing
//                            is ranked
//   output            [in] - Verbose keeps the top 10 rule names in each ranking; Summary keeps 3
//   countFilters      [in] - returns the filter and filter-condition counts for one rule name;
//                            called once per distinct name
//
// Returns:
//   The two rankings, the limit used, and filtersLoadResult.
//
FilterRankings
AnalyzeFilterRankings(
    const std::vector<NormalizedFirewallRule>& rules,
    HRESULT filtersLoadResult,
    AnalysisOutput output,
    const FilterCounter& countFilters)
{
	FilterRankings rankings;
	rankings.filtersLoadResult = filtersLoadResult;
	rankings.limit = output == AnalysisOutput::Verbose ? 10 : 3;
	if (FAILED(filtersLoadResult))
	{
		return rankings;
	}

	std::vector<const NormalizedFirewallRule*> byName;
	byName.reserve(rules.size());
	for (const auto& rule : rules)
	{
		byName.push_back(&rule);
	}
	std::ranges::stable_sort(
	    byName,
	    [](const NormalizedFirewallRule* lhs, const NormalizedFirewallRule* rhs)
	    {
		    return lhs->rule_name < rhs->rule_name;
	    });

	std::vector<RankedRuleName> ruleNames;
	for (auto first = byName.begin(); first != byName.end();)
	{
		const auto& name = (*first)->rule_name;
		const auto last = std::find_if(
		    first,
		    byName.end(),
		    [&name](const NormalizedFirewallRule* rule)
		    {
			    return !(rule->rule_name == name);
		    });

		const auto counts = countFilters(name);
		RankedRuleName ruleName{
		    .ruleName = name.value,
		    .ruleCount = static_cast<size_t>(last - first),
		    .filterCount = counts.filterCount,
		    .filterConditionCount = counts.filterConditionCount};
		for (auto rule = first; rule != last; ++rule)
		{
			ruleName.ruleIds.push_back((*rule)->fw_rule->wszRuleId);
		}
		ruleNames.push_back(std::move(ruleName));
		first = last;
	}

	rankings.byFilterCount = TopRuleNames(ruleNames, rankings.limit, &RankedRuleName::filterCount);
	rankings.byFilterConditionCount = TopRuleNames(ruleNames, rankings.limit, &RankedRuleName::filterConditionCount);
	return rankings;
}

//
// PrintFilterRankings
//
// Formats one store's rankings as console text.
//
// Parameters:
//   rankings [in] - the result of AnalyzeFilterRankings
//
// Returns:
//   Both rankings, each preceded by a blank line and a heading; a ranking with no entries is
//   left out. When the filters could not be read, one line saying the rankings were skipped,
//   with the error code. Empty when there is nothing to report.
//
std::wstring
PrintFilterRankings(const FilterRankings& rankings)
{
	std::wstring text;
	if (FAILED(rankings.filtersLoadResult))
	{
		text += std::format(
		    L"\n  * Skipping the filter rankings: WFP filters could not be read (0x{:08X})\n",
		    static_cast<uint32_t>(rankings.filtersLoadResult));
		return text;
	}

	PrintRanking(
	    text,
	    L"WFP filter count",
	    rankings.limit,
	    rankings.byFilterCount,
	    &RankedRuleName::filterCount,
	    L"filters");
	PrintRanking(
	    text,
	    L"WFP filter-condition count",
	    rankings.limit,
	    rankings.byFilterConditionCount,
	    &RankedRuleName::filterConditionCount,
	    L"conditions");
	return text;
}
