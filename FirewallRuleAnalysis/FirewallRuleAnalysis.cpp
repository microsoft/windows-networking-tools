/*
 * FwRuleAnalysis
 *
 * - Provides users the ability to find redundancies and inconsistencies in the Windows Firewall rules
 *
 */
#include <algorithm>
#include <chrono>
#include <iostream>
#include <vector>

#include <Windows.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/resource.h>

#include "FirewallRuleBuilder.h"

class ChronoTimer
{
public:
	void begin() noexcept
	{
		m_startTime_ns = std::chrono::high_resolution_clock::now();
	}

	// returns in milliseconds
	long long end() const noexcept
	{
		const auto endTime_ns = std::chrono::high_resolution_clock::now();
		// Convert nanoseconds to milliseconds
		return std::chrono::duration_cast<std::chrono::milliseconds>(endTime_ns - m_startTime_ns).count();
	}
private:
	decltype(std::chrono::high_resolution_clock::now()) m_startTime_ns;
};

inline std::vector<NormalizedRuleInfo> BuildFirewallRules(_In_ INetFwRules* firewallRules)
{
	std::vector<NormalizedRuleInfo> returnInfo;
	uint32_t enum_count{ 0 };

	wil::com_ptr<IEnumVARIANT> enumRules;
	THROW_IF_FAILED(firewallRules->get__NewEnum(enumRules.put_unknown()));

	// enumerators (IEnum*) loop until Next() returns S_FALSE
	for (HRESULT nextResult = S_OK; nextResult == S_OK;)
	{
		// show progress by a . for every 100 rules
		if (enum_count % 100 == 0)
		{
			wprintf(L".");
		}
		++enum_count;

		wil::unique_variant nextInstance;
		ULONG fetched{};
		nextResult = enumRules->Next(1, nextInstance.addressof(), &fetched);
		THROW_IF_FAILED(nextResult);
		if (nextResult == S_OK)
		{
			wil::com_ptr<INetFwRule3> nextRule;
			THROW_IF_FAILED(nextInstance.punkVal->QueryInterface<INetFwRule3>(&nextRule));
			auto ruleInfo = BuildFirewallRuleInfo(nextRule.get());
			// add if successfully read the entire rule
			if (ruleInfo.rule)
			{
				returnInfo.emplace_back(std::move(ruleInfo));
			}
		}
	}

	return returnInfo;
}

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
void DeleteDuplicateRules(
	_In_ INetFwRules* firewallRules,
	std::vector<NormalizedRuleInfo>& normalized_rules, // non-const as we set a boolean when we need to temporarily rename a rule
	const std::vector<NormalizedRuleInfo>::iterator& duplicate_rule_begin,
	const std::vector<NormalizedRuleInfo>::iterator& duplicate_rule_end)
{
	wprintf(
		L"\nDeleting %lld duplicates for the rule:\n"
		L"\tName: %ws\n"
		L"\tDescription: %ws\n"
		L"\tDirection: %ws\n"
		L"\tEnabled: %ws\n",
		duplicate_rule_end - duplicate_rule_begin - 1,
		duplicate_rule_begin->ruleName.get(),
		duplicate_rule_begin->ruleDescription.get(),
		duplicate_rule_begin->ruleDirection == NET_FW_RULE_DIR_IN ? L"Inbound" : L"Outbound",
		duplicate_rule_begin->ruleEnabled ? L"Enabled" : L"Disabled");

	wprintf(L">> Press Y key to continue to delete duplicates of this rule - else any other key to skip this rule <<\n");
	std::wstring input;
	std::getline(std::wcin, input);
	if (input != L"y" && input != L"Y")
	{
		wprintf(L" >> skipping this rule <<\n");
		return;
	}

	// first, temporarily rename all rules that we don't want to accidentally delete
	// i.e., keep the rules (duplicate_rule_begin + 1) to (duplicateRuleEndIterator - 1)
	const auto& ruleNameToKeep = duplicate_rule_begin->ruleName;
	const auto tempRuleName = wil::make_bstr((std::wstring(ruleNameToKeep.get()) + L"__temp__").c_str());

	uint32_t countOfRulesRenamed = 0;
	// nothing in the loop should throw - so that we can put all names back that we temporarily renamed
	for (auto it = normalized_rules.begin(); it != normalized_rules.end(); ++it)
	{
		// ignore this rule if we have previously deleted it
		if (it->ruleDeleted)
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
				wprintf(L"FAILED TO RENAME ORIGINAL RULE: %ws (0x%x)\n", it->ruleName.get(), hr);
				break;
			}
			it->temporarilyRenamed = true;
			++countOfRulesRenamed;
			continue;
		}

		// check if the name matches the rule we want to clear of duplicates
		// - if it matches, we need to take extra steps to not accidentally delete this rule
		//   as it just happens to have the same name (but otherwise is not a duplicate)
		if (!RuleNamesMatch(it->ruleName, ruleNameToKeep))
		{
			continue;
		}
		// TESTING code to fail-fast if we have a bug --> at this stage
		if (RulesMatchExactly(*it, *(duplicate_rule_begin + 1)))
		{
			wprintf(
				L"BUG: these rules should not match!!\n"
				L"\tName: %ws\n"
				L"\tDescription: %ws\n"
				L"\tDirection: %ws\n"
				L"\tEnabled: %ws\n",
				it->ruleName.get(),
				it->ruleDescription.get(),
				it->ruleDirection == NET_FW_RULE_DIR_IN ? L"Inbound" : L"Outbound",
				it->ruleEnabled ? L"Enabled" : L"Disabled");
			FAIL_FAST();
		}
		// rename the rule that happens to have the same name as the duplicate rules we want to remove
		const auto hr = it->rule->put_Name(tempRuleName.get());
		if (FAILED(hr))
		{
			wprintf(L"\tFAILED TO RENAME EXTRA RULE: %ws (0x%x)\n", it->ruleName.get(), hr);
			break;
		}
		it->temporarilyRenamed = true;
		++countOfRulesRenamed;
	}

	wprintf(L"-- Renamed %lu rules to avoid deleting them unnecessarily (including the one we want to keep)\n", countOfRulesRenamed);

	uint32_t deletedRules = 0;
	for (auto it = duplicate_rule_begin + 1; it != duplicate_rule_end; ++it)
	{
		const auto hr = firewallRules->Remove(it->ruleName.get());
		if (FAILED(hr))
		{
			wprintf(L"\tFAILED TO REMOVE RULE: %ws (0x%x)\n", it->ruleName.get(), hr);
		}
		else
		{
			it->ruleDeleted = true;
			++deletedRules;
		}
	}

	wprintf(L"-- Deleted %u rules that were duplicates\n", deletedRules);

	// rename all temp rules back before we exit
	uint32_t restoredRuleNames = 0;
	for (auto& normalized_rule : normalized_rules)
	{
		if (normalized_rule.temporarilyRenamed)
		{
			const auto hr = normalized_rule.rule->put_Name(ruleNameToKeep.get());
			if (FAILED(hr))
			{
				wprintf(L"\tFAILED TO RENAME RULE BACK TO ITS ORIGINAL NAME: %ws (0x%x)\n", normalized_rule.ruleName.get(), hr);
			}
			else
			{
				++restoredRuleNames;
			}
		}

		normalized_rule.temporarilyRenamed = false;
	}
	wprintf(L"-- Renamed %u rules back to their original names that had been temporarily renamed\n", restoredRuleNames);
}

void PrintHelp() noexcept
{
	wprintf(
		L"Usage (optional): [-includeDetails] [-deleteDuplicates] [-exactMatches]\n");
	wprintf(
		L"  -includeDetails: Print detailed information about the duplicates found\n");
	wprintf(
		L"  -exactMatches: Only find exact matches (all fields except 'Enabled' must match)\n");
	wprintf(
		L"  -deleteDuplicates: deletes duplicate rules that are exact matches (all fields except 'Enabled' must match)\n"
		L"                     currently requires also setting -exactMatches\n"
		L"                     if any duplicate rule is Enabled, will keep an Enabled version of that rule\n");
}

int wmain(int argc, wchar_t** argv)
try
{
	/*
	 *  support cleaning all rules that match exactly (every field)
	 *  support finding near-matches
	 *   - e.g. the first X characters in a rule match
	 */
	enum class MatchType
	{
		ExactMatch,
		OnlyDetailsMatch
	};

	std::optional<bool> printDetails;
	std::optional<bool> deleteDuplicates;
	std::optional<MatchType> matchType;
	if (argc > 1)
	{
		const std::vector<const wchar_t*> args(argv + 1, argv + argc);
		for (const auto& arg : args)
		{
			if (0 == _wcsicmp(arg, L"-help") || 0 == _wcsicmp(arg, L"-?"))
			{
				PrintHelp();
				return 0;
			}

			if (0 == _wcsicmp(arg, L"-includeDetails"))
			{
				if (printDetails.has_value())
				{
					// they specified the same arg twice!
					PrintHelp();
					return 1;
				}

				printDetails = true;
			}
			else if (0 == _wcsicmp(arg, L"-deleteDuplicates"))
			{
				if (deleteDuplicates.has_value())
				{
					// they specified the same arg twice!
					PrintHelp();
					return 1;
				}

				deleteDuplicates = true;
			}
			else if (0 == _wcsicmp(arg, L"-exactMatches"))
			{
				if (matchType.has_value())
				{
					// they specified the same arg twice!
					PrintHelp();
					return 1;
				}

				matchType = MatchType::ExactMatch;
			}
			else
			{
				wprintf(L"Unknown argument: %ws\n\n", arg);
				PrintHelp();
				return 1;
			}
		}
	}

	if (deleteDuplicates.has_value() && !matchType.has_value())
	{
		wprintf(L"Error: -deleteDuplicates requires -exactMatches\n\n");
		PrintHelp();
		return 1;
	}

	if (!printDetails.has_value())
	{
		printDetails = false;
	}
	if (!deleteDuplicates.has_value())
	{
		deleteDuplicates = false;
	}
	if (!matchType.has_value())
	{
		matchType = MatchType::OnlyDetailsMatch;
	}

	const auto unInit = wil::CoInitializeEx();
	const auto firewallPolicy = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();
	wil::com_ptr<INetFwRules> firewallRules{};
	THROW_IF_FAILED(firewallPolicy->get_Rules(&firewallRules));

	ChronoTimer timer;
	timer.begin();
	std::vector<NormalizedRuleInfo> normalizedRules = BuildFirewallRules(firewallRules.get());
	wprintf(L"\n  Querying for rules took %lld milliseconds to read %lld rules\n", timer.end(), normalizedRules.size());

	/*
	 *  support processing of Service-rules
	 */
	 /*
	 wil::com_ptr<INetFwServiceRestriction> serviceRestriction{};
	 THROW_IF_FAILED(firewallPolicy->get_ServiceRestriction(&serviceRestriction));
	 THROW_IF_FAILED(serviceRestriction->get_Rules(&rules));
	 std::vector<NormalizedRuleInfo> normalizedServiceRules = BuildFirewallRules(firewallRules.get());
	 */

	 // find duplicates - excluding the name and if they are enabled or not
	for (const auto pass : { MatchType::ExactMatch, MatchType::OnlyDetailsMatch })
	{
		if (matchType.value() == MatchType::ExactMatch && pass != MatchType::ExactMatch)
		{
			continue;
		}
		if (matchType.value() == MatchType::OnlyDetailsMatch && pass != MatchType::OnlyDetailsMatch)
		{
			continue;
		}

		wprintf(L"\n----------------------------------------------------------------------------------------------------\n");
		if (pass == MatchType::OnlyDetailsMatch)
		{
			wprintf(L"Processing Firewall rules - looking for rules that are duplicated, only matching key fields\n (not comparing the 'Name', 'Description', and 'Enabled' fields)");
		}
		else
		{
			wprintf(L"Processing Firewall rules - looking for rules that are duplicated, exactly matching all fields\n (except the field 'Enabled' - will match identical rules Enabled and Disabled)");
		}
		wprintf(L"\n----------------------------------------------------------------------------------------------------\n");

		size_t totalRulesWithDuplicates{ 0 };
		size_t sumOfAllDuplicateRules{ 0 };

		timer.begin();
		// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
		std::ranges::sort(normalizedRules, pass == MatchType::OnlyDetailsMatch ? SortOnlyMatchingDetails : SortExactMatches);

		for (auto currentIterator = normalizedRules.begin();;)
		{
			// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
			const auto duplicateRuleBeginIterator{
				std::adjacent_find(
					currentIterator,
					normalizedRules.end(),
					pass == MatchType::OnlyDetailsMatch ? RuleDetailsMatch : RulesMatchExactly) };
			if (duplicateRuleBeginIterator == normalizedRules.cend())
			{
				// if adjacent_find returns the end iterator, there are no more adjacent entries that match
				// in which case we should break out of the for loop
				break;
			}

			++totalRulesWithDuplicates;

			// duplicateRuleIterator is currently pointing to the first of x number of duplicate rules
			// start from duplicateRuleIterator and walk forward until the rule doesn't match
			// i.e., currentIterator will be pointing one-past-the-last-matching-rule
			currentIterator = duplicateRuleBeginIterator;
			while (currentIterator != normalizedRules.end())
			{
				// iterate through normalizedRules until we hit the end of the vector or until RuleDetailsMatch returns false
				// i.e., we found the iterator past the last duplicate
				if (!RuleDetailsMatch(*currentIterator, *(currentIterator + 1)))
				{
					break;
				}
				++currentIterator;
			}
			// the loop breaks when currentIterator matches currentIterator + 1
			// incrementing currentIterator so it points to next-rule-past the one that matched
			++currentIterator;

			// this should never happen since adjacent_find identified at least 2 rules that match
			FAIL_FAST_IF(currentIterator == duplicateRuleBeginIterator);

			// give the 'end' iterator of the duplicates a name that doesn't confuse with the currentIterator
			const auto duplicateRuleEndIterator = currentIterator;
			const auto duplicateRuleCount{ duplicateRuleEndIterator - duplicateRuleBeginIterator };
			sumOfAllDuplicateRules += duplicateRuleCount;

			if (printDetails.value())
			{
				wprintf(L"\nDuplicate rule found! Count of duplicates of this rule (%lld)\n", duplicateRuleCount);
				for (auto printIterator = duplicateRuleBeginIterator; printIterator != duplicateRuleEndIterator; ++printIterator)
				{
					wprintf(L"\t[%ws %ws] name: %ws, description: %ws\n",
						printIterator->ruleDirection == NET_FW_RULE_DIR_IN ? L"INBOUND" : L"OUTBOUND",
						printIterator->ruleEnabled ? L"ENABLED" : L"DISABLED",
						printIterator->ruleName.get(), printIterator->ruleDescription.get());
				}
			}

			if (deleteDuplicates.value())
			{
				DeleteDuplicateRules(
					firewallRules.get(),
					normalizedRules,
					duplicateRuleBeginIterator,
					duplicateRuleEndIterator);
			}
		}
		const auto timeToProcess = timer.end();

		if (pass == MatchType::OnlyDetailsMatch)
		{
			wprintf(L"\nResults from analyzing Firewall rules that match only rule key fields (e.g. not comparing name and description fields):\n");
		}
		else
		{
			wprintf(L"\nResults from analyzing Firewall rules that exactly match all rule fields:\n");
		}

		wprintf(
			L"\tTotal Firewall rules processed: %llu\n"
			L"\tFirewall rules with duplicates: %llu\n"
			L"\tTotal of all duplicate Firewall rules: %llu\n",
			normalizedRules.size(),
			totalRulesWithDuplicates,
			sumOfAllDuplicateRules);

		if (!deleteDuplicates.value())
		{
			wprintf(L"\n... parsing rules took %lld milliseconds\n", timeToProcess);
		}

		wprintf(L"\n... count of rule comparisons that required a deep CompareString call: %u\n", RuleDetailsDeepMatchComparisonCount);
	}
}
CATCH_RETURN()
