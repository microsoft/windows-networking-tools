// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "DuplicateAnalysis.h"

#include <algorithm>
#include <cwchar>
#include <format>
#include <ranges>

namespace
{
//
// CompareRuleIds
//
// Orders two rule IDs, treating a missing ID as before any other.
//
// Parameters:
//   lhs [in] - a rule ID, or nullptr
//   rhs [in] - a rule ID, or nullptr
//
// Returns:
//   A negative value, zero, or a positive value, as for wcscmp.
//
int
CompareRuleIds(PCWSTR lhs, PCWSTR rhs) noexcept
{
	if (!lhs || !rhs)
	{
		return (lhs ? 1 : 0) - (rhs ? 1 : 0);
	}
	return std::wcscmp(lhs, rhs);
}

//
// IsOrderedByNameThenId
//
// The order of rules within a set of duplicate rules, and of the sets themselves (by their first rule).
//
// Parameters:
//   lhs [in] - a rule
//   rhs [in] - another rule
//
// Returns:
//   true when lhs belongs before rhs: alphabetically by normalized name, then by rule ID.
//
bool
IsOrderedByNameThenId(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
	const auto names = NormalizedString::AlphabeticalCompare(lhs.rule_name, rhs.rule_name);
	if (names != 0)
	{
		return names < 0;
	}
	return CompareRuleIds(lhs.fw_rule->wszRuleId, rhs.fw_rule->wszRuleId) < 0;
}
} // namespace

//
// AnalyzeDuplicateRules
//
// Finds the sets of rules that match on every setting except rule ID, name, description, and schema
// version (RuleDetailsComparison with comparison_policy_compare_all).
//
// Parameters:
//   rules [in, out] - the store's rules; sorted in place so that each set of duplicate rules is
//                     adjacent, and within a set by name and then by rule ID
//
// Returns:
//   The sets of duplicate rules, ordered by the name of their first rule, and how many rules they
//   hold. The sets refer into rules, which must not be reordered while the result is in use.
//
DuplicateAnalysis
AnalyzeDuplicateRules(std::vector<NormalizedFirewallRule>& rules)
{
	std::ranges::sort(
	    rules,
	    [](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
	    {
		    const auto comparison = RuleDetailsComparison(lhs, rhs);
		    if (comparison != 0)
		    {
			    return comparison < 0;
		    }
		    return IsOrderedByNameThenId(lhs, rhs);
	    });

	DuplicateAnalysis analysis;
	for (auto first = rules.begin(); first != rules.end();)
	{
		const auto last = std::find_if(
		    first + 1,
		    rules.end(),
		    [&first](const NormalizedFirewallRule& rule) noexcept
		    {
			    return RuleDetailsComparison(*first, rule) != 0;
		    });
		if (last - first > 1)
		{
			DuplicateRuleSet set{.duplicate_rule_begin = first, .duplicate_rule_end = last, .nameCount = 1};
			for (auto rule = first + 1; rule != last; ++rule)
			{
				if (!(rule->rule_name == (rule - 1)->rule_name))
				{
					++set.nameCount;
				}
			}
			analysis.duplicateRuleCount += static_cast<size_t>(last - first);
			analysis.duplicateSets.push_back(set);
		}
		first = last;
	}

	std::ranges::sort(
	    analysis.duplicateSets,
	    [](const DuplicateRuleSet& lhs, const DuplicateRuleSet& rhs) noexcept
	    {
		    return IsOrderedByNameThenId(*lhs.duplicate_rule_begin, *rhs.duplicate_rule_begin);
	    });
	return analysis;
}

//
// PrintDuplicateAnalysis
//
// Formats one store's duplicate analysis as console text.
//
// Parameters:
//   analysis [in] - the result of AnalyzeDuplicateRules
//   output   [in] - Verbose prints the counts even when there are no duplicates, and lists every set
//
// Returns:
//   The summary heading and counts, and for Verbose one line per set: its rule count, the name of its
//   first rule (or its rule ID when it has no name), its application when it has one, and how many
//   different names its rules have when there is more than one. Empty for Summary output when there
//   are no duplicates.
//
std::wstring
PrintDuplicateAnalysis(const DuplicateAnalysis& analysis, AnalysisOutput output)
{
	const bool verbose = output == AnalysisOutput::Verbose;
	if (!verbose && analysis.duplicateSets.empty())
	{
		return {};
	}

	std::wstring text = L"  * Summary of duplicate analysis of firewall rules:\n";
	text += std::format(L"   - count of sets of duplicate rules: {}\n", analysis.duplicateSets.size());
	text += std::format(L"   - count of rules in sets of duplicate rules: {}\n", analysis.duplicateRuleCount);
	if (!verbose || analysis.duplicateSets.empty())
	{
		return text;
	}

	text += L"   - sets of duplicate rules:\n";
	for (const auto& set : analysis.duplicateSets)
	{
		const auto& rule = *set.duplicate_rule_begin;
		text += std::format(
		    L"       [{} rules] {}:  {}",
		    set.duplicate_rule_end - set.duplicate_rule_begin,
		    rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
		    rule.rule_name.value.empty() ? FirewallRuleTextToString(rule.fw_rule->wszRuleId) : rule.rule_name.value);
		if (rule.fw_rule->wszLocalApplication && rule.fw_rule->wszLocalApplication[0] != L'\0')
		{
			text += std::format(L"  (Application-exe: '{}')", rule.fw_rule->wszLocalApplication);
		}
		if (set.nameCount > 1)
		{
			text += std::format(L"  [{} different names]", set.nameCount);
		}
		text += L"\n";
	}
	return text;
}
