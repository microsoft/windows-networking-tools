#pragma once

#include <netfw.h>
#include <vector>
#include <wil/com.h>

#include "NormalizedFirewallRule.h"

NormalizedFirewallRule BuildFirewallRuleInfo(const wil::com_ptr<INetFwRule3>& rule) noexcept;

inline std::vector<NormalizedFirewallRule> BuildFirewallRulesViaCom(
    _In_ INetFwRules* firewallRules, bool printDebugInfo)
{
    std::vector<NormalizedFirewallRule> returnInfo;
    uint32_t enum_count{0};

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

            auto ruleInfo{BuildFirewallRuleInfo(nextRule.get())};
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
