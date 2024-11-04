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

// appx-created rules start with:
// @{
// and contain the resource id string:
// ms-resource://
// these are not managed by the public COM API, unfortunately
bool IsRuleAnAppxRule(const NormalizedRuleInfo& ruleInfo)
{
	if (!ruleInfo.ruleName.is_valid())
	{
		return false;
	}

	const auto bstrString = ruleInfo.ruleName.get();
	const auto stringLength = SysStringLen(bstrString);
	//18 == length of '@{' (2) + length of 'ms-resource://' (14)
	if (stringLength < 16)
	{
		return false;
	}
	if (bstrString[0] != L'@' || bstrString[1] != '{')
	{
		return false;
	}

	// now search for ms-resource://  --- this is case-sensitive, but that seems correct for APPX rules
	return std::wstring(bstrString).find(L"ms-resource://") != std::wstring::npos;
}

std::vector<NormalizedRuleInfo> BuildFirewallRules(_In_ INetFwRules* firewallRules, bool printDebugInfo)
{
	std::vector<NormalizedRuleInfo> returnInfo;
	uint32_t enum_count{ 0 };

	if (printDebugInfo)
	{
		wprintf(L"\t[[INetFwRules::get__NewEnum]]\n");
	}
	wil::com_ptr<IEnumVARIANT> enumRules;
	THROW_IF_FAILED(firewallRules->get__NewEnum(enumRules.put_unknown()));

	// enumerators (IEnum*) loop until Next() returns S_FALSE
	for (HRESULT nextResult = S_OK; nextResult == S_OK;)
	{
		// show progress by a . for every 100 rules
		if (!printDebugInfo)
		{
			if (enum_count % 100 == 0)
			{
				wprintf(L".");
			}
		}

		// ensuring an array of wil::unique_variant is functionally equivalent to an array of VARIANT
		static_assert(sizeof(wil::unique_variant) == sizeof(VARIANT));
		ULONG fetched{};
		wil::unique_variant retrievedInstances[500];
		nextResult = enumRules->Next(500, retrievedInstances, &fetched);
		THROW_IF_FAILED(nextResult);

		if (printDebugInfo)
		{
			wprintf(L"\t[[IEnumVARIANT::Next >> read the next %lu rules]]\n", fetched);
		}

		for (ULONG fetched_count = 0; fetched_count < fetched; ++fetched_count)
		{
			// QI the rule to the latest version INetFwRule
			wil::com_ptr<INetFwRule3> nextRule;
			THROW_IF_FAILED(retrievedInstances[fetched_count].punkVal->QueryInterface<INetFwRule3>(&nextRule));

			auto ruleInfo = BuildFirewallRuleInfo(nextRule.get());
			// add if successfully read the entire rule
			if (ruleInfo.rule)
			{
				returnInfo.emplace_back(std::move(ruleInfo));
			}
		}

		enum_count += fetched;
	}

	return returnInfo;
}

void PrintRuleInformation(const NormalizedRuleInfo& ruleInfo) noexcept
{
	wprintf(
		L"\t[%ws | %ws]\n"
		L"\t [name]: %ws\n"
		L"\t [description]: %ws\n"
		L"\t [ownerUsername]: %ws\n",
		ruleInfo.ruleDirection == NET_FW_RULE_DIR_IN ? L"INBOUND" : L"OUTBOUND",
		ruleInfo.ruleEnabled ? L"ENABLED" : L"DISABLED",
		ruleInfo.ruleName.get(),
		ruleInfo.ruleDescription.get(),
		ruleInfo.ruleOwnerUsername.empty() ? L"<empty>" : ruleInfo.ruleOwnerUsername.c_str());
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
	bool promptBeforeDeleting,
	_In_ INetFwRules* firewallRules,
	std::vector<NormalizedRuleInfo>& normalized_rules, // non-const as we set a boolean when we need to temporarily rename a rule
	const std::vector<NormalizedRuleInfo>::iterator& duplicate_rule_begin,
	const std::vector<NormalizedRuleInfo>::iterator& duplicate_rule_end)
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

		// TESTING code to fail-fast if we have a bug --> at this stage
		if (RulesMatchExactly(*it, *(duplicate_rule_begin + 1)))
		{
			wprintf(L"BUG: these rules should not match!!\n");
			PrintRuleInformation(*it);
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

void PrintHelp() noexcept
{
	wprintf(
		L"Usage (optional): [-exactMatches] [-deleteDuplicates]\n"
		L"\n"
		L"  [default] prints all duplicate rules (both exact matches and loose matches)\n"
		L"    Exact matches are duplicate rules matching all rule properties except 'Enabled'\n"
		L"    Loose matches are duplicate rules matching all rule properties except 'Enabled', 'Name', and 'Description'\n"
		L"\n"
		L"  -exactMatches: prints rules (or deletes rules if -deleteDuplicates) that are exact matches \n"
		L"  -deleteDuplicates: if -exactMatches is specified, automatically deletes all exact duplicate rules\n"
		L"                   : if -exactMatches is not specified, will prompt for deleting any/all duplicate rules\n"
		L"\n"
	);
}

int wmain(int argc, wchar_t** argv)
try
{
	const auto comInit = wil::CoInitializeEx();

	/*
	 *  consider supporting finding near-matches
	 *   - e.g. the first X characters in a rule match
	 */
	enum class MatchType
	{
		ExactMatch, // all fields except Enabled match
		LooseMatch  // all fields except Enabled, Name, and Description match
	};

	std::optional<bool> deleteDuplicates;
	std::optional<MatchType> matchType;
	std::optional<bool> printDebugInfo;
	if (argc > 1)
	{
		const std::vector<const wchar_t*> args(argv + 1, argv + argc);
		for (const auto& arg : args)
		{
			if (0 == _wcsicmp(arg, L"-help") || 0 == _wcsicmp(arg, L"-?") || 0 == _wcsicmp(arg, L"/help") || 0 == _wcsicmp(arg, L"/?"))
			{
				PrintHelp();
				return 0;
			}

			if (0 == _wcsicmp(arg, L"-deleteDuplicates") || 0 == _wcsicmp(arg, L"/deleteDuplicates"))
			{
				if (deleteDuplicates.has_value())
				{
					// they specified the same arg twice!
					PrintHelp();
					return 1;
				}

				deleteDuplicates = true;
			}
			else if (0 == _wcsicmp(arg, L"-exactMatches") || 0 == _wcsicmp(arg, L"/exactMatches"))
			{
				if (matchType.has_value())
				{
					// they specified the same arg twice!
					PrintHelp();
					return 1;
				}

				matchType = MatchType::ExactMatch;
			}
			else if (0 == _wcsicmp(arg, L"-debug") || 0 == _wcsicmp(arg, L"/debug"))
			{
				if (printDebugInfo.has_value())
				{
					// they specified the same arg twice!
					PrintHelp();
					return 1;
				}

				printDebugInfo = true;
			}
			else
			{
				wprintf(L"Unknown argument: %ws\n\n", arg);
				PrintHelp();
				return 1;
			}
		}
	}

	if (!deleteDuplicates.has_value())
	{
		deleteDuplicates = false;
	}
	if (!matchType.has_value())
	{
		matchType = MatchType::LooseMatch;
	}
	if (!printDebugInfo.has_value())
	{
		printDebugInfo = false;
	}

	ChronoTimer timer;
	timer.begin();
	if (printDebugInfo.value())
	{
		wprintf(L"\t[[CoCreateInstance(INetFwPolicy2)]]\n");
	}
	const auto firewallPolicy = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();
	if (printDebugInfo.value())
	{
		wprintf(L"\t[[INetFwPolicy2::get_Rules]]\n");
	}
	wil::com_ptr<INetFwRules> firewallRules{};
	THROW_IF_FAILED(firewallPolicy->get_Rules(&firewallRules));
	std::vector<NormalizedRuleInfo> normalizedRules = BuildFirewallRules(firewallRules.get(), printDebugInfo.value());
	wprintf(L"\n>> Querying for rules took %lld milliseconds to read %lld rules <<\n", timer.end(), normalizedRules.size());

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
	for (const auto pass : { MatchType::ExactMatch, MatchType::LooseMatch })
	{
		if (matchType.value() == MatchType::ExactMatch && pass != MatchType::ExactMatch)
		{
			continue;
		}
		if (matchType.value() == MatchType::LooseMatch && pass != MatchType::LooseMatch)
		{
			continue;
		}

		if (pass == MatchType::LooseMatch)
		{
			wprintf(L"\n");
			wprintf(L"--------------------------------------------------------------------------------------------------\n");
			wprintf(L"  Processing Firewall rules : looking for rules that are duplicated - not requiring an exact match\n");
			wprintf(L"  Ignoring the rule properties 'Name', 'Description', and 'Enabled' when matching rules\n");
			wprintf(L"--------------------------------------------------------------------------------------------------\n");
		}
		else
		{
			wprintf(L"\n");
			wprintf(L"----------------------------------------------------------------------------------------------\n");
			wprintf(L"  Processing Firewall rules : looking for rules that are duplicated - requiring an exact match\n");
			wprintf(L"  Ignoring the rule property 'Enabled' when matching rules\n");
			wprintf(L"----------------------------------------------------------------------------------------------\n");
		}

		size_t totalRulesWithDuplicates{ 0 };
		size_t sumOfAllDuplicateRules{ 0 };

		timer.begin();
		// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
		std::ranges::sort(normalizedRules, pass == MatchType::LooseMatch ? SortOnlyMatchingDetails : SortExactMatches);

		for (auto currentIterator = normalizedRules.begin();;)
		{
			// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
			const auto duplicateRuleBeginIterator{
				std::adjacent_find(
					currentIterator,
					normalizedRules.end(),
					pass == MatchType::LooseMatch ? RuleDetailsMatch : RulesMatchExactly) };
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

			const auto appxRule = IsRuleAnAppxRule(*duplicateRuleBeginIterator);
			wprintf(
				L"\nFound (%lld) copies of this %ws:\n",
				duplicateRuleCount,
				appxRule ? L"APPX rule" : L"local rule");
			PrintRuleInformation(*duplicateRuleBeginIterator);

			if (deleteDuplicates.value())
			{
				if (appxRule)
				{
					wprintf(L">> Cannot directly delete APPX rules - must analyze directly in the registry <<\n");
				}
				else
				{
					const auto promptBeforeDeleting = matchType.value() == MatchType::LooseMatch;
					DeleteDuplicateRules(
						promptBeforeDeleting,
						firewallRules.get(),
						normalizedRules,
						duplicateRuleBeginIterator,
						duplicateRuleEndIterator);
				}
			}
		}
		const auto timeToProcess = timer.end();

		if (pass == MatchType::LooseMatch)
		{
			wprintf(L"\nResults from analyzing Firewall rules that match only rule key fields (e.g. not comparing name and description fields):\n");
		}
		else
		{
			wprintf(L"\nResults from analyzing Firewall rules that exactly match all rule fields:\n");
		}

		wprintf(
			L"\tTotal Firewall rules processed: %llu\n"
			L"\tUnique firewall rules with duplicates: %llu\n"
			L"\tTotal of all the different duplicate Firewall rules: %llu\n",
			normalizedRules.size(),
			totalRulesWithDuplicates,
			sumOfAllDuplicateRules);

		if (printDebugInfo.value())
		{
			wprintf(L"\n");
			if (!deleteDuplicates.value())
			{
				if (timeToProcess > 0)
				{
					wprintf(L"\t[[sorting and parsing rules took %lld milliseconds]]\n", timeToProcess);
				}
				else
				{
					wprintf(L"\t[[sorting and parsing rules took less than 1 millisecond]]\n");
				}
			}
			wprintf(L"\t[[count of rule comparisons that required a deep CompareString call: %u]]\n", RuleDetailsDeepMatchComparisonCount);
		}
	}
}
CATCH_RETURN()
