#pragma once
#include <cwchar>
#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/resource.h>

#include "NormalizedFirewallRule.h"

// The only API to remove a rule is INetFwRules::Remove, but that takes the Name of a rule
// this is problematic because the Name property of Firewall Rules is not guaranteed to be unique
// (the COM Name property matches the WMI/Powershell property DisplayName)
// Thus using the COM API, we can't control *exactly* which rule to remove when we pass it the name
// To get around this, we must first temporarily rename all the rules matching the Name
// that we don't want to accidentally delete
// - i.e., we only keep the duplicate Rules with the identified name
//   we must rename the first 'duplicate' since that's the one rule of the duplicates to keep
//   we must rename all the other non-duplicate rules that happen to have the same name
//   (so they are not accidentally deleted)
inline void DeleteDuplicateRulesViaCom(
	bool promptBeforeDeleting,
	_In_ INetFwRules* firewallRules,
	std::vector<NormalizedFirewallRule>& normalized_rules, // non-const as we set a boolean when we need to temporarily rename a rule
	const std::vector<NormalizedFirewallRule>::iterator& duplicate_rule_begin,
	const std::vector<NormalizedFirewallRule>::iterator& duplicate_rule_end)
{
	const auto ruleCountToDelete = duplicate_rule_end - duplicate_rule_begin - 1;
	if (promptBeforeDeleting)
	{
		wprintf(L">> Press Y key to continue to delete %lld duplicates of this rule - else any other key to skip this rule <<\n", ruleCountToDelete);
		std::wstring input;
		std::getline(std::wcin, input);
		if (input != L"y" && input != L"Y")
		{
			wprintf(L" >> skipping this rule <<\n");
			return;
		}
	}

	// first, temporarily rename all rules that we don't want to accidentally delete
	// i.e., keep the rules (duplicate_rule_begin + 1) to (duplicateRuleEndIterator - 1)
	const auto& ruleNameToKeep = duplicate_rule_begin->ruleName;
	const auto tempRuleName = wil::make_bstr((std::wstring(ruleNameToKeep.get()) + L"__temp__").c_str());

	// Temporarily renaming the rule we want to keep kept back + any unrelated rules
	// since INetFwRules::Remove is given only the rule name - to delete the duplicates

	// nothing in the loop should throw - so that we can put all names back that we temporarily renamed
	for (auto it = normalized_rules.begin(); it != normalized_rules.end(); ++it)
	{
		// ignore this rule if we have previously deleted it
		if (!it->rule)
		{
			continue;
		}

		// check if it is pointing to a rule we want to delete (one of the duplicates)
		if (it > duplicate_rule_begin && it < duplicate_rule_end)
		{
			continue;
		}

		// check if 'it' is pointing to the one rule we want to keep
		// if so, rename it so we don't accidentally delete it
		if (it == duplicate_rule_begin)
		{
			// this is the rule we eventually want to keep after removing the other duplicates
			const auto hr = it->rule->put_Name(tempRuleName.get());
			if (FAILED(hr))
			{
				wprintf(L">> FAILED TO RENAME ORIGINAL RULE: %ws (0x%x) <<\n", it->ruleName.get(), hr);
				break;
			}

			it->temporarilyRenamed = true;
			continue;
		}

		// check if the name matches the rule we want to clear of duplicates
		// - if it matches, we need to take extra steps to not accidentally delete this rule
		//   as it just happens to have the same name (but otherwise is not a duplicate)
		if (!RuleNamesMatch(it->ruleName, ruleNameToKeep))
		{
			continue;
		}

		if (RulesMatchExactly(*it, *(duplicate_rule_begin + 1)))
		{
			wprintf(L"BUG: these rules should not match!!\n");
            PrintNormalizedFirewallRule(*it);
    		// TESTING code to fail-fast if we have a bug
			FAIL_FAST();
		}

		// rename the rule that happens to have the same name as the duplicate rules we want to remove
		const auto hr = it->rule->put_Name(tempRuleName.get());
		if (FAILED(hr))
		{
			wprintf(L">> FAILED TO RENAME EXTRA RULE: %ws (0x%x) <<\n", it->ruleName.get(), hr);
			THROW_HR(hr);
		}

		it->temporarilyRenamed = true;
	}

	long initialCount = 0;
	firewallRules->get_Count(&initialCount);

	uint32_t deletedRules = 0;
	for (auto it = duplicate_rule_begin + 1; it != duplicate_rule_end; ++it)
	{
		const auto hr = firewallRules->Remove(it->ruleName.get());
		if (FAILED(hr))
		{
			wprintf(L">> FAILED TO REMOVE RULE: %ws (0x%x) <<\n", it->ruleName.get(), hr);
		}
		else
		{
			// close the COM object once we have deleted the corresponding rule
			it->rule.reset();
			++deletedRules;
		}
	}
	long finalCount = 0;
	firewallRules->get_Count(&finalCount);

	if (initialCount == finalCount)
	{
		wprintf(L">> INetFwRules::Remove(%ws) succeeded - but the current rule count is the same! Firewall did not delete the rules!", ruleNameToKeep.get());
	}
	else
	{
		if (deletedRules == 1)
		{
			wprintf(L">> Successfully deleted 1 duplicate <<\n");
		}
		else
		{
			wprintf(L">> Successfully deleted %u duplicates <<\n", deletedRules);
		}
	}

	// rename all temp rules back before we exit
	for (auto& normalized_rule : normalized_rules)
	{
		if (normalized_rule.temporarilyRenamed)
		{
			const auto hr = normalized_rule.rule->put_Name(ruleNameToKeep.get());
			if (FAILED(hr))
			{
				wprintf(L">> FAILED TO RENAME RULE BACK TO ITS ORIGINAL NAME: %ws (0x%x) <<\n", normalized_rule.ruleName.get(), hr);
			}
			normalized_rule.temporarilyRenamed = false;
		}
	}
}

