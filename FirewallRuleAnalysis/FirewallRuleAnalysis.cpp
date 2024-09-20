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
	std::vector<NormalizedRuleInfo> returnInfo;

    long count{};
    THROW_IF_FAILED(rules->get_Count(&count));

    // enumerators loop until S_FALSE
    wil::com_ptr<IEnumVARIANT> enumVariant;
    THROW_IF_FAILED(rules->get__NewEnum(enumVariant.put_unknown()));
    HRESULT nextResult{S_OK};
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

int main()
try
{
    const auto uninit = wil::CoInitializeEx();

	const auto firewallPolicy = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();

	wil::com_ptr<INetFwRules> rules{};
	THROW_IF_FAILED(firewallPolicy->get_Rules(&rules));
	std::vector<NormalizedRuleInfo> normalizedRules = BuildFirewallRules(rules.get());

	wil::com_ptr<INetFwServiceRestriction> serviceRestriction{};
	THROW_IF_FAILED(firewallPolicy->get_ServiceRestriction(&serviceRestriction));
	THROW_IF_FAILED(serviceRestriction->get_Rules(&rules));
	std::vector<NormalizedRuleInfo> normalizedServiceRules = BuildFirewallRules(rules.get());

    // now sort and find duplicates
	std::sort(normalizedRules.begin(), normalizedRules.end());
    std::sort(normalizedServiceRules.begin(), normalizedServiceRules.end());

    // find duplicates
	uint32_t rulesWithDuplicates{};
	uint32_t sumOfAllDuplicates{};
	std::vector<NormalizedRuleInfo>::iterator startingIterator = normalizedRules.begin();
    for (;;)
    {
		auto duplicateRuleIterator = std::adjacent_find(startingIterator, normalizedRules.end());
		if (duplicateRuleIterator == normalizedRules.cend())
		{
			break;
		}
        ++rulesWithDuplicates;

		// find all duplicates of this instance
        auto localDuplicateIterator = duplicateRuleIterator;
        uint32_t localDuplicateRuleCount{};
        for (;;)
        {
	        if (*localDuplicateIterator != *(localDuplicateIterator + 1))
	        {
				startingIterator = localDuplicateIterator + 1;
                break;
			}
            ++localDuplicateRuleCount;
			++localDuplicateIterator;
        }

		sumOfAllDuplicates += localDuplicateRuleCount;
		wprintf(L"\nDuplicate rule found! Duplicate count (%u)\n", localDuplicateRuleCount);

    	// startingIterator is now updated to the next rule after the duplicates
		while (duplicateRuleIterator != startingIterator)
		{
			wprintf(L"\tname: %ws, description: %ws\n", duplicateRuleIterator->ruleName.get(), duplicateRuleIterator->ruleDescription.get());
            ++duplicateRuleIterator;
        }
    }

	wprintf(L"\n\nTotal rules: %llu\nRules with duplicates: %u\nTotal of all duplicate rules: %u\n", normalizedRules.size(), rulesWithDuplicates, sumOfAllDuplicates);
}
CATCH_RETURN()