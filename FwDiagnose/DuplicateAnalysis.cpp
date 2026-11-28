// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "DuplicateAnalysis.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <format>
#include <iterator>
#include <optional>
#include <ranges>
#include <utility>

#include "FwDiagnose.h"

namespace
{
//
// RuleNameOrId
//
// Parameters:
//   rule [in] - the rule to identify
//
// Returns:
//   How the console identifies a rule: "Rule Name:  <normalized name>", or
//   "(no Rule Name) RuleId:  <rule ID>" when it has no name.
//
std::wstring
RuleNameOrId(const NormalizedFirewallRule& rule)
{
	return rule.rule_name.value.empty()
	           ? L"(no Rule Name) RuleId:  " + FirewallRuleTextToString(rule.fw_rule->wszRuleId)
	           : L"Rule Name:  " + rule.rule_name.value;
}

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
		text +=
		    std::format(L"       [{} rules] {}", set.duplicate_rule_end - set.duplicate_rule_begin, RuleNameOrId(rule));
		if (rule.fw_rule->wszLocalApplication && rule.fw_rule->wszLocalApplication[0] != L'\0')
		{
			text += std::format(L"  (Application-exe: '{}')", rule.fw_rule->wszLocalApplication);
		}
		if (set.nameCount > 1)
		{
			text += std::format(L"  [{} different names]", set.nameCount);
		}
		text += L'\n';
	}
	return text;
}

//
// ReturnDuplicateKeepChoices
//
// Lists the names a user can choose between when deleting all but one rule of a set.
//
// Parameters:
//   set [in] - one set of duplicate rules from AnalyzeDuplicateRules
//
// Returns:
//   One choice per different (case-insensitive) name, ordered alphabetically, each with the position of
//   the first rule in the set that has that name. Rules without a name are one choice, labeled by the
//   rule ID of the first of them, so the list never shows an empty entry.
//
std::vector<DuplicateKeepChoice>
ReturnDuplicateKeepChoices(const DuplicateRuleSet& set)
{
	std::vector<std::pair<const NormalizedFirewallRule*, size_t>> firstRuleOfEachName;
	size_t ruleIndex = 0;
	for (auto rule = set.duplicate_rule_begin; rule != set.duplicate_rule_end; ++rule, ++ruleIndex)
	{
		const auto sameName = [&rule](const std::pair<const NormalizedFirewallRule*, size_t>& first)
		{
			return first.first->rule_name == rule->rule_name;
		};
		if (std::ranges::none_of(firstRuleOfEachName, sameName))
		{
			firstRuleOfEachName.emplace_back(&*rule, ruleIndex);
		}
	}

	// stable, so equal names keep set order; an empty name sorts first
	std::ranges::stable_sort(
	    firstRuleOfEachName,
	    [](const std::pair<const NormalizedFirewallRule*, size_t>& lhs,
	       const std::pair<const NormalizedFirewallRule*, size_t>& rhs)
	    {
		    return NormalizedString::AlphabeticalCompare(lhs.first->rule_name, rhs.first->rule_name) < 0;
	    });

	std::vector<DuplicateKeepChoice> choices;
	for (const auto& [rule, index] : firstRuleOfEachName)
	{
		choices.push_back(
		    {.label = rule->rule_name.value.empty() ? RuleNameOrId(*rule) : rule->rule_name.value, .ruleIndex = index});
	}
	return choices;
}

//
// DeleteDuplicateRules
//
// Asks, for each set of duplicate rules, whether to delete all but one rule of the set, and deletes them.
// When the rules of a set have different names, also asks which name to keep; otherwise the first rule
// of the set is kept. Deleted rules are marked is_rule_deleted, and each failure is printed and passed
// to RecordOperationFailure.
//
// Parameters:
//   analysis   [in] - the result of AnalyzeDuplicateRules; the rules it refers to are updated
//   input      [in] - where the answers are read from: std::wcin, or a scripted stream in tests. When it
//                     ends, nothing more is deleted without an answer: a y/n/s/a prompt counts as 's',
//                     and a set waiting for the name to keep is left alone.
//   deleteRule [in] - deletes one rule by rule ID; FWDeleteFirewallRule on the store's handle, or a
//                     fake in tests
//
void
DeleteDuplicateRules(
    const DuplicateAnalysis& analysis, std::wistream& input, const DeleteFirewallRuleFunction& deleteRule)
{
	bool printed_deletion_header = false;
	bool delete_all_with_no_more_prompts = false;

	for (const auto& set : analysis.duplicateSets)
	{
		const auto duplicate_rule_total = std::distance(set.duplicate_rule_begin, set.duplicate_rule_end);
		FAIL_FAST_IF(duplicate_rule_total == 0);

		if (!printed_deletion_header)
		{
			printed_deletion_header = true;
			PrintDeletionHeader("Deleting duplicate rules");
		}

		std::printf(
		    "\n"
		    "     %zd duplicates of this rule [%ls]\n",
		    duplicate_rule_total,
		    RuleNameOrId(*set.duplicate_rule_begin).c_str());

		if (!delete_all_with_no_more_prompts)
		{
			switch (PromptForDeletion(DeletionPrompt, input))
			{
			case PromptResponse::Yes:
				// continue to delete the duplicates of this rule
				break;

			case PromptResponse::No:
				std::printf("       - Skipping this rule\n");
				continue;

			case PromptResponse::Skip:
				std::printf("       - Skipping the remainder of the duplicate rules in this store\n");
				return;

			case PromptResponse::All:
				std::printf("       - Deleting all duplicate rules in this store\n");
				delete_all_with_no_more_prompts = true;
				break;
			}
		}

		// keep the first rule, unless the names differ: then ask the user which name to keep
		size_t rule_to_keep = 0;
		const auto choices = ReturnDuplicateKeepChoices(set);
		if (choices.size() > 1)
		{
			std::printf("\n     Duplicate rules have different names. Please choose which to keep:\n");
			for (size_t choice = 0; choice < choices.size(); ++choice)
			{
				std::printf("       %zu. %ls\n", choice + 1, choices[choice].label.c_str());
			}

			std::optional<size_t> chosen_rule;
			std::wstring userInput;
			while (!chosen_rule.has_value())
			{
				std::printf("       Enter the number of the rule to keep: ");
				userInput.clear();
				if (!std::getline(input, userInput))
				{
					break;
				}

				// anything that is not a listed number asks again
				const auto entered_choice = std::wcstoul(userInput.c_str(), nullptr, 10);
				if (entered_choice >= 1 && entered_choice <= choices.size())
				{
					chosen_rule = choices[entered_choice - 1].ruleIndex;
				}
			}

			if (!chosen_rule.has_value())
			{
				std::printf("\n       - No more input - keeping all of these rules\n");
				continue;
			}
			rule_to_keep = chosen_rule.value();
		}

		std::printf("       Deleting %zd duplicates of this rule, keeping 1\n", duplicate_rule_total - 1);

		uint32_t successful_deletion_counter = 0;
		size_t rule_index = 0;
		for (auto rule = set.duplicate_rule_begin; rule != set.duplicate_rule_end; ++rule, ++rule_index)
		{
			if (rule_index == rule_to_keep)
			{
				std::printf("        Keeping [%ls]\n", RuleNameOrId(*rule).c_str());
				continue;
			}

			const auto deleteRuleError = deleteRule(rule->fw_rule->wszRuleId);
			if (deleteRuleError != ERROR_SUCCESS)
			{
				std::printf(
				    "        Failed to delete one of the duplicate firewall rules (0x%lx) - RuleId %ls\n",
				    HRESULT_FROM_WIN32(deleteRuleError),
				    FirewallRuleTextToString(rule->fw_rule->wszRuleId).c_str());
				RecordOperationFailure(HRESULT_FROM_WIN32(deleteRuleError));
			}
			else
			{
				rule->is_rule_deleted = true;
				++successful_deletion_counter;
				if (VerboseOutputEnabled())
				{
					std::printf(
					    "        Successfully deleted the duplicate firewall rule RuleId %ls\n",
					    FirewallRuleTextToString(rule->fw_rule->wszRuleId).c_str());
				}
			}
		}

		if (successful_deletion_counter > 0)
		{
			std::printf("        Successfully deleted %u duplicate firewall rules\n", successful_deletion_counter);
		}
	}
}