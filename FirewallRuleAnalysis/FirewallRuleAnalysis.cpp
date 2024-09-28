/*
 * FwRuleAnalysis
 *
 * - Provides users the ability to find rundancies and inconsistencies in the Windows Firewall rules
 *
 */
#include <algorithm>
#include <chrono>
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

inline std::vector<NormalizedRuleInfo> BuildFirewallRules(_In_ INetFwPolicy2* firewallPolicy)
{
	std::vector<NormalizedRuleInfo> returnInfo;
	uint32_t enum_count{ 0 };

	wil::com_ptr<INetFwRules> rules{};
	THROW_IF_FAILED(firewallPolicy->get_Rules(&rules));

	wil::com_ptr<IEnumVARIANT> enumRules;
	THROW_IF_FAILED(rules->get__NewEnum(enumRules.put_unknown()));

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
			if ((0 == _wcsicmp(arg, L"-help")) || (0 == _wcsicmp(arg, L"-?")))
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

	ChronoTimer timer;
	const auto unInit = wil::CoInitializeEx();
	const auto firewallPolicy = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();

	timer.begin();
	std::vector<NormalizedRuleInfo> normalizedRules = BuildFirewallRules(firewallPolicy.get());
	wprintf(L"\n... querying for rules took %lld milliseconds\n", timer.end());

	/*
	 *  support processing of Service-rules
	 */
	 /*
	 wil::com_ptr<INetFwServiceRestriction> serviceRestriction{};
	 THROW_IF_FAILED(firewallPolicy->get_ServiceRestriction(&serviceRestriction));
	 THROW_IF_FAILED(serviceRestriction->get_Rules(&rules));
	 std::vector<NormalizedRuleInfo> normalizedServiceRules = BuildFirewallRules(rules.get());
	 */

	timer.begin();
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

		uint32_t rulesWithDuplicates{ 0 };
		uint32_t sumOfAllDuplicates{ 0 };

		timer.begin();
		// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
		std::ranges::sort(normalizedRules, pass == MatchType::OnlyDetailsMatch ? SortOnlyMatchingDetails : SortExactMatches);
		auto currentIterator = normalizedRules.begin();
		for (;;)
		{
			// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
			auto duplicateRuleIterator{
				std::adjacent_find(
					currentIterator,
					normalizedRules.end(),
					pass == MatchType::OnlyDetailsMatch ? RuleDetailsMatch : RulesMatchExactly) };
			if (duplicateRuleIterator == normalizedRules.cend())
			{
				break;
			}

			++rulesWithDuplicates;
			// find all duplicates of this instance
			auto localDuplicateIterator = duplicateRuleIterator;
			uint32_t localDuplicateRuleCount{ 1 };
			for (;;)
			{
				if (!RuleDetailsMatch(*localDuplicateIterator, *(localDuplicateIterator + 1)))
				{
					// update currentIterator to point to the next rule after the current duplicates
					currentIterator = localDuplicateIterator + 1;
					break;
				}

				++localDuplicateRuleCount;
				++localDuplicateIterator;
			}
			// if our sorting and comparison functions are correct, this should always find at least one duplicate
			FAIL_FAST_IF(localDuplicateRuleCount == 1);

			// upon exiting the for loop, startingIterator is updated to point to the next rule after the current duplicates
			sumOfAllDuplicates += localDuplicateRuleCount;

			// give the 'end' iterator of the duplicates a name that doesn't confuse with the currentIterator
			const auto duplicateRuleEndIterator = currentIterator;
			FAIL_FAST_IF(localDuplicateRuleCount != duplicateRuleEndIterator - duplicateRuleIterator);

			if (printDetails.value())
			{
				wprintf(L"\nDuplicate rule found! Duplicate count (%u)\n", localDuplicateRuleCount);
				while (duplicateRuleIterator != duplicateRuleEndIterator)
				{
					wprintf(L"\t[%ws %ws] name: %ws, description: %ws\n",
						duplicateRuleIterator->ruleDirection == NET_FW_RULE_DIR_IN ? L"INBOUND" : L"OUTBOUND",
						duplicateRuleIterator->ruleEnabled ? L"ENABLED" : L"DISABLED",
						duplicateRuleIterator->ruleName.get(), duplicateRuleIterator->ruleDescription.get());
					++duplicateRuleIterator;
				}
			}

			if (deleteDuplicates.value())
			{
				wprintf(
					L"\nDeleting duplicates for the rule:\n"
					L"\tName: %ws\n"
					L"\tDescription: %ws\n"
					L"\tDirection: %ws\n"
					L"\tEnabled: %ws\n",
					duplicateRuleIterator->ruleName.get(),
					duplicateRuleIterator->ruleDescription.get(),
					duplicateRuleIterator->ruleDirection == NET_FW_RULE_DIR_IN ? L"Inbound" : L"Outbound",
					duplicateRuleIterator->ruleEnabled ? L"Enabled" : L"Disabled");

				wil::com_ptr<INetFwRules> rules{};
				THROW_IF_FAILED(firewallPolicy->get_Rules(&rules));

				// The only API to remove a rule is INetFwRules::Remove
				// but that takes the Name of a rule
				// this is problematic because we can't control *exactly* which rule to remove
				// - there might be another rule with the same name but not in this set of duplicate rules
				// - we can't control which duplicate to remove - so we must track if any are enabled
				//   and once only one remains, we must enable it

				// first scan every name that's not part of this set of duplicates
				bool nonDuplicateWithConflictingName = false;
				for (auto it = normalizedRules.begin(); it != normalizedRules.end(); ++it)
				{
					if (it >= duplicateRuleIterator && it < duplicateRuleEndIterator)
					{
						// skip this one - it's one of the duplicates
						continue;
					}

					if (RulesNamesMatch(*it, *duplicateRuleIterator))
					{
						nonDuplicateWithConflictingName = true;
						// this is a rule with the same name but not part of this set of duplicates
						wprintf(
							L"Cannot delete duplicates because found a different rule matching same name but is NOT an exact duplicate\n"
							L"\tName: %ws\n"
							L"\tDescription: %ws\n"
							L"\tDirection: %ws\n"
							L"\tEnabled: %ws\n",
							it->ruleName.get(),
							it->ruleDescription.get(),
							it->ruleDirection == NET_FW_RULE_DIR_IN ? L"Inbound" : L"Outbound",
							it->ruleEnabled ? L"Enabled" : L"Disabled");
						break;
					}
				}

				// delete only if there are no other rules that happen to have the same name
				if (!nonDuplicateWithConflictingName)
				{
					// second, track if the final remaining rule should be enabled or disabled after we delete all duplicates
					const auto ruleShouldBeEnabled = duplicateRuleIterator->ruleEnabled;
					const auto& ruleNameToDelete = duplicateRuleIterator->ruleName.get();
					const auto totalDuplicateRuleCount = duplicateRuleEndIterator - duplicateRuleIterator;

					// third, delete all the duplicates
					// TESTING: should be > 0, but keeping > 1 for testing
					for (auto count = totalDuplicateRuleCount; count > 1; --count)
					{
						THROW_IF_FAILED(rules->Remove(ruleNameToDelete));
					}

					// fourth, enable the final remaining rule if it's not already set to be enabled
					if (ruleShouldBeEnabled && !duplicateRuleIterator->ruleEnabled)
					{
						const auto hr = duplicateRuleIterator->rule->put_Enabled(VARIANT_TRUE);
						if (SUCCEEDED(hr))
						{
							wprintf(L"\tenabled the final remaining rule for %ws\n", duplicateRuleIterator->ruleName.get());
						}
						else
						{
							wprintf(L"\tfailed to enable the final remaining rule for %ws (0x%x)\n", duplicateRuleIterator->ruleName.get(), hr);
						}
					}
				}

				// TESTING: setting this back to false, so we only try to delete one duplicate ruleset
				deleteDuplicates = false;
			}
		}

		if (pass == MatchType::OnlyDetailsMatch)
		{
			wprintf(L"\nResults from analyzing Firewall rules that match only rule key fields (e.g. not comparing name and description fields)\n"
				"\t(count of rule comparisons that required a deep CompareString call: %u)\n", RuleDetailsDeepMatchComparisonCount);
		}
		else
		{
			wprintf(L"\nResults from analyzing Firewall rules that exactly match all rule fields\n");
		}

		wprintf(
			L"\tTotal Firewall rules processed: %llu\n\tFirewall rules with duplicates: %u\n\tTotal of all duplicate Firewall rules: %u\n",
			normalizedRules.size(),
			rulesWithDuplicates,
			sumOfAllDuplicates);
	}
	wprintf(L"\n... parsing rules took %lld milliseconds\n", timer.end());
}
CATCH_RETURN()
