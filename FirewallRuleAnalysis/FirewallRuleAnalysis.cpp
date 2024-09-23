/*
 * FwRuleAnalysis
 *
 * - Provides users the ability to find rundancies and inconsistencies in the Windows Firewall rules
 *
 */
#include <algorithm>
#include <iostream>
#include <vector>

#include <Windows.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/resource.h>

#include "FirewallRuleBuilder.h"

inline std::vector<NormalizedRuleInfo> BuildFirewallRules(_In_ INetFwRules* rules)
{
	long count{};
	THROW_IF_FAILED(rules->get_Count(&count));

	std::vector<NormalizedRuleInfo> returnInfo;
	returnInfo.reserve(count);

	wil::com_ptr<IEnumVARIANT> enumVariant;
	THROW_IF_FAILED(rules->get__NewEnum(enumVariant.put_unknown()));
	HRESULT nextResult{ S_OK };
	// enumerators (IEnum*) loop until S_FALSE
	while (nextResult == S_OK)
	{
		wil::unique_variant nextInstance;
		ULONG fetched{};
		nextResult = enumVariant->Next(1, nextInstance.addressof(), &fetched);
		THROW_IF_FAILED(nextResult);
		if (nextResult == S_OK)
		{
			wil::com_ptr<INetFwRule> nextRule;
			THROW_IF_FAILED(nextInstance.punkVal->QueryInterface<INetFwRule>(&nextRule));
			returnInfo.emplace_back(BuildFirewallRuleInfo(nextRule.get()));
		}
	}

	return returnInfo;
}

void PrintHelp() noexcept
{
	wprintf(L"Usage (optional): [-includeDetails] [-exactMatches]\n");
	wprintf(L"  -includeDetails: Print detailed information about the duplicates found\n");
	wprintf(L"  -exactMatches: Only find exact matches (all fields must match)\n");
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
				wprintf(L"Unknown argument: %ws\n", arg);
				PrintHelp();
				return 1;
			}
		}
	}

	if (!printDetails.has_value())
	{
		printDetails = false;
	}
	if (!matchType.has_value())
	{
		matchType = MatchType::OnlyDetailsMatch;
	}

	const auto unInit = wil::CoInitializeEx();
	const auto firewallPolicy = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();
	wil::com_ptr<INetFwRules> rules{};
	THROW_IF_FAILED(firewallPolicy->get_Rules(&rules));

	std::vector<NormalizedRuleInfo> normalizedRules = BuildFirewallRules(rules.get());

	/*
	 *  support processing of Service-rules
	 */
	 /*
	 wil::com_ptr<INetFwServiceRestriction> serviceRestriction{};
	 THROW_IF_FAILED(firewallPolicy->get_ServiceRestriction(&serviceRestriction));
	 THROW_IF_FAILED(serviceRestriction->get_Rules(&rules));
	 std::vector<NormalizedRuleInfo> normalizedServiceRules = BuildFirewallRules(rules.get());
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
			std::ranges::sort(normalizedRules, SortOnlyMatchingDetails);
		}
		else
		{
			wprintf(L"Processing Firewall rules - looking for rules that are duplicated, exactly matching all fields\n (except the field 'Enabled' - will match identical rules Enabled and Disabled)");
			std::ranges::sort(normalizedRules, SortExactMatches);
		}
		wprintf(L"\n----------------------------------------------------------------------------------------------------\n");

		uint32_t rulesWithDuplicates{};
		uint32_t sumOfAllDuplicates{};
		std::vector<NormalizedRuleInfo>::iterator startingIterator = normalizedRules.begin();
		for (;;)
		{
			std::vector<NormalizedRuleInfo>::iterator duplicateRuleIterator{};

			if (pass == MatchType::OnlyDetailsMatch)
			{
				duplicateRuleIterator = std::adjacent_find(startingIterator, normalizedRules.end(), RuleDetailsMatch);
			}
			else
			{
				duplicateRuleIterator = std::adjacent_find(startingIterator, normalizedRules.end(), RulesMatchExactly);
			}

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
					startingIterator = localDuplicateIterator + 1;
					break;
				}

				++localDuplicateRuleCount;
				++localDuplicateIterator;
			}
			// if our sorting and comparison functions are correct, this should always find at least one duplicate
			FAIL_FAST_IF(localDuplicateRuleCount == 1);
			// upon exiting the for loop, startingIterator is updated to point to the next rule after the current duplicates
			sumOfAllDuplicates += localDuplicateRuleCount;

			if (printDetails.value())
			{
				wprintf(L"\nDuplicate rule found! Duplicate count (%u)\n", localDuplicateRuleCount);
				while (duplicateRuleIterator != startingIterator)
				{
					wprintf(L"\t[%ws %ws] name: %ws, description: %ws\n",
						duplicateRuleIterator->ruleDirection == NET_FW_RULE_DIR_IN ? L"INBOUND" : L"OUTBOUND",
						duplicateRuleIterator->ruleEnabled ? L"ENABLED" : L"DISABLED",
						duplicateRuleIterator->ruleName.get(), duplicateRuleIterator->ruleDescription.get());
					++duplicateRuleIterator;
				}
			}
		}

		if (pass == MatchType::OnlyDetailsMatch)
		{
			wprintf(L"\nResults from analyzing Firewall rules that match only rule key fields (e.g. not comparing name and description fields)\n");
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

}
CATCH_RETURN()