// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstddef>
#include <istream>
#include <string>
#include <vector>

#include <Windows.h>

#include "AnalysisOutput.h"
#include "NormalizedFirewallRule.h"
#include "RuleDeletion.h"

// rules that match on every setting except rule ID, name, description, and schema version
struct DuplicateRuleSet
{
	// the rules of one set are adjacent in the analyzed vector, ordered by name and then by rule ID
	std::vector<NormalizedFirewallRule>::iterator duplicate_rule_begin;
	std::vector<NormalizedFirewallRule>::iterator duplicate_rule_end;
	// how many different (case-insensitive) names the rules have
	size_t nameCount{};
};

struct DuplicateAnalysis
{
	// ordered by the name of their first rule; the iterators refer to the analyzed rules, which must
	// not be reordered while the analysis is in use
	std::vector<DuplicateRuleSet> duplicateSets;
	// the rules in all sets, including the one rule per set that -clean-rules keeps
	size_t duplicateRuleCount{};
};

DuplicateAnalysis
AnalyzeDuplicateRules(std::vector<NormalizedFirewallRule>& rules);

std::wstring
PrintDuplicateAnalysis(const DuplicateAnalysis& analysis, AnalysisOutput output);

// one name the user can choose to keep when the rules of a set have different names
struct DuplicateKeepChoice
{
	// the normalized name, or "(no Rule Name) RuleId:  <rule ID>" for rules without a name
	std::wstring label;
	// the position within the set of the first rule with this name; that rule is the one kept
	size_t ruleIndex{};
};

std::vector<DuplicateKeepChoice>
ReturnDuplicateKeepChoices(const DuplicateRuleSet& set);

void
DeleteDuplicateRules(
    const DuplicateAnalysis& analysis, std::wistream& input, const DeleteFirewallRuleFunction& deleteRule);
