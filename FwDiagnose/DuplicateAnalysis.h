// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <vector>

#include "AnalysisOutput.h"
#include "NormalizedFirewallRule.h"

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
