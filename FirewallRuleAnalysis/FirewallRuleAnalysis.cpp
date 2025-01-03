/*
 * FwRuleAnalysis
 *
 * - Provides users the ability to find redundancies and inconsistencies in the Windows Firewall rules
 *
 */
#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

#include <Windows.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/registry.h>
#include <wil/resource.h>

#include "NormalizedFirewallRule.h"
#include "BuildFirewallRulesViaCOM.h"
#include "BuildFirewallRulesViaRegistry.h"
#include "DeleteDuplicateRulesFromCom.h"

namespace details
{
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

enum class MatchType
{
    ExactMatch, // all fields except Enabled match
    LooseMatch // all fields except Enabled, Name, and Description match
};

bool g_PrintDebugInfo = false;
bool g_DeleteDuplicates = false;
MatchType g_MatchType = MatchType::ExactMatch;

void ParseInputParameters(const std::vector<const wchar_t*>& args)
{
    std::optional<bool> localPrintDebugInfo;
    std::optional<bool> localDeleteDuplicates;
    std::optional<MatchType> localMatchType;

    if (!args.empty())
    {
        for (const auto& arg : args)
        {
            if (0 == _wcsicmp(arg, L"-help") || 0 == _wcsicmp(arg, L"-?") || 0 == _wcsicmp(arg, L"/help") || 0 ==
                _wcsicmp(arg, L"/?"))
            {
                PrintHelp();
                THROW_HR(E_INVALIDARG);
            }

            if (0 == _wcsicmp(arg, L"-deleteDuplicates") || 0 == _wcsicmp(arg, L"/deleteDuplicates"))
            {
                if (localDeleteDuplicates.has_value())
                {
                    // they specified the same arg twice!
                    PrintHelp();
                    THROW_HR(E_INVALIDARG);
                }

                localDeleteDuplicates = true;
            }
            else if (0 == _wcsicmp(arg, L"-exactMatches") || 0 == _wcsicmp(arg, L"/exactMatches"))
            {
                if (localMatchType.has_value())
                {
                    // they specified the same arg twice!
                    PrintHelp();
                    THROW_HR(E_INVALIDARG);
                }

                localMatchType = MatchType::ExactMatch;
            }
            else if (0 == _wcsicmp(arg, L"-debug") || 0 == _wcsicmp(arg, L"/debug"))
            {
                if (localPrintDebugInfo.has_value())
                {
                    // they specified the same arg twice!
                    PrintHelp();
                    THROW_HR(E_INVALIDARG);
                }

                localPrintDebugInfo = true;
            }
            else
            {
                wprintf(L"Unknown argument: %ws\n\n", arg);
                PrintHelp();
                THROW_HR(E_INVALIDARG);
            }
        }
    }

    if (localPrintDebugInfo.has_value())
    {
        g_PrintDebugInfo = localPrintDebugInfo.value();
    }
    if (localDeleteDuplicates.has_value())
    {
        g_DeleteDuplicates = localDeleteDuplicates.value();
    }
    if (localMatchType.has_value())
    {
        g_MatchType = localMatchType.value();
    }
}

/*
 *  consider supporting finding near-matches
 *   - e.g. the first X characters in a rule match
 */

int __cdecl wmain(int argc, wchar_t** argv)
try
{
    ParseInputParameters(std::vector<const wchar_t*>{argv + 1, argv + argc});

    const auto comInit = wil::CoInitializeEx();

    wil::com_ptr<INetFwRules> firewallRules{};
    std::vector<NormalizedFirewallRule> INetFwNormalizedRules;
    details::ChronoTimer timer;

    timer.begin();
    {
        if (g_PrintDebugInfo)
        {
            wprintf(L"\t[[CoCreateInstance(INetFwPolicy2)]]\n");
        }

        const auto firewallPolicy = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();
        if (g_PrintDebugInfo)
        {
            wprintf(L"\t[[INetFwPolicy2::get_Rules]]\n");
        }

        THROW_IF_FAILED(firewallPolicy->get_Rules(&firewallRules));
        INetFwNormalizedRules = BuildFirewallRulesViaCom(firewallRules.get(), g_PrintDebugInfo);
    }
    wprintf(
        L"\n>> Querying for rules took %lld milliseconds to read %lld rules <<\n",
        timer.end(),
        INetFwNormalizedRules.size());

    // find duplicates - excluding the name and if they are enabled or not
    if (g_MatchType == MatchType::LooseMatch)
    {
        wprintf(L"\n");
        wprintf(
            L"----------------------------------------------------------------------------------------------------\n");
        wprintf(
            L"  Processing Firewall rules : looking for rules that are duplicated - not requiring an exact match\n");
        wprintf(L"  Ignoring the rule properties 'Name', 'Description', and 'Enabled' when matching rules\n");
        wprintf(
            L"----------------------------------------------------------------------------------------------------\n");
    }
    else
    {
        wprintf(L"\n");
        wprintf(
            L"------------------------------------------------------------------------------------------------\n");
        wprintf(
            L"  Processing Firewall rules : looking for rules that are duplicated - requiring an exact match\n");
        wprintf(L"  Ignoring the rule property 'Enabled' when matching rules\n");
        wprintf(
            L"------------------------------------------------------------------------------------------------\n");
    }

    wprintf(L">> Reading Local Firewall rules from the registry <<\n");
    timer.begin();
    const auto registryFirewallRules = BuildFirewallRulesViaRegistry(FirewallRuleRegistryStore::Local);
    wprintf(
        L">> Parsing registry rules from the registry took %lld milliseconds to read %lld rules <<\n",
        timer.end(),
        registryFirewallRules.size());

    size_t totalRulesWithDuplicates = CountDuplicateFirewallRules(registryFirewallRules);
    wprintf(L">> %llu duplicate Local Firewall rules\n", totalRulesWithDuplicates);

    wprintf(L"\n");

    wprintf(L">> Reading App-Isolation Firewall rules from the registry <<\n");
    timer.begin();
    const auto appIsolationRegistryFirewallRules = BuildFirewallRulesViaRegistry(
        FirewallRuleRegistryStore::AppIsolation);
    wprintf(
        L">> Reading registry rules took %lld milliseconds to read %lld rules <<\n",
        timer.end(),
        appIsolationRegistryFirewallRules.size());

    totalRulesWithDuplicates = CountDuplicateFirewallRules(appIsolationRegistryFirewallRules);
    wprintf(L">> %llu duplicate App-Isolation Firewall rules\n", totalRulesWithDuplicates);

    totalRulesWithDuplicates = 0;
    timer.begin();
    // the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
    std::ranges::sort(INetFwNormalizedRules, g_MatchType == MatchType::LooseMatch ? SortOnlyMatchingDetails : SortExactMatches);

    size_t sumOfAllDuplicateRules{0};
    for (auto currentIterator = INetFwNormalizedRules.begin(); currentIterator != INetFwNormalizedRules.end();)
    {
        // the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
        const auto duplicateRuleBeginIterator{
            std::adjacent_find(
                currentIterator,
                INetFwNormalizedRules.end(),
                g_MatchType == MatchType::LooseMatch ? RuleDetailsMatch : RulesMatchExactly)
        };
        if (duplicateRuleBeginIterator == INetFwNormalizedRules.cend())
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
        while (currentIterator != INetFwNormalizedRules.end())
        {
            if (currentIterator + 1 == INetFwNormalizedRules.end())
            {
                break;
            }
            // iterate through normalizedRules until we hit the end of the vector or until RuleDetailsMatch returns false
            // i.e., we found the iterator past the last duplicate
            if (!RuleDetailsMatch(*currentIterator, *(currentIterator + 1)))
            {
                break;
            }
            ++currentIterator;
        }
        // the loop breaks when currentIterator matches currentIterator + 1, or when hitting the end
        // incrementing currentIterator so it points to next-rule-past the one that matched
        if (currentIterator != INetFwNormalizedRules.end())
        {
            ++currentIterator;
        }

        // this should never happen since adjacent_find identified at least 2 rules that match
        FAIL_FAST_IF(currentIterator == duplicateRuleBeginIterator);

        // give the 'end' iterator of the duplicates a name that doesn't confuse with the currentIterator
        const auto duplicateRuleEndIterator = currentIterator;
        const auto duplicateRuleCount{duplicateRuleEndIterator - duplicateRuleBeginIterator};
        sumOfAllDuplicateRules += duplicateRuleCount;

        const auto appxRule = IsRuleAnAppxRule(*duplicateRuleBeginIterator);
        wprintf(
            L"\nFound (%lld) copies of this %ws:\n",
            duplicateRuleCount,
            appxRule ? L"APPX rule" : L"local rule");
        PrintNormalizedFirewallRule(*duplicateRuleBeginIterator);

        if (appxRule)
        {
            std::vector<std::wstring> matchingLocalValues;
            std::vector<std::wstring> matchingAppIsolationValues;

            wprintf(L"\n");
            wprintf(L"\t>> Cannot directly delete APPX rules - must analyze directly in the local registry <<\n");
            uint32_t localRegistryMatches = 0;
            for (const auto& [registryValue, ruleInfo] : registryFirewallRules)
            {
                if (ruleInfo.ruleEnabled != duplicateRuleBeginIterator->ruleEnabled)
                {
                    continue;
                }
                if (ruleInfo.ruleDirection != duplicateRuleBeginIterator->ruleDirection)
                {
                    continue;
                }
                if (!RuleNamesMatch(ruleInfo.ruleName, duplicateRuleBeginIterator->ruleName))
                {
                    continue;
                }
                if (!RuleNamesMatch(ruleInfo.ruleDescription, duplicateRuleBeginIterator->ruleDescription))
                {
                    continue;
                }
                // PrintRuleInformation(ruleInfo);

                matchingLocalValues.emplace_back(registryValue);
                ++localRegistryMatches;
            }
            wprintf(L"\t>> total local registry matches: %u\n", localRegistryMatches);
            for (const auto& value : matchingLocalValues)
            {
                wprintf(L"\t     %ws\n", value.c_str());
            }
            wprintf(L"\n");

            wprintf(
                L"\t>> Cannot directly delete APPX rules - must analyze directly in the App-Isolation registry <<\n");
            uint32_t appIsolationRegistryMatches = 0;
            for (const auto& [registryValue, ruleInfo] : appIsolationRegistryFirewallRules)
            {
                if (ruleInfo.ruleEnabled != duplicateRuleBeginIterator->ruleEnabled)
                {
                    continue;
                }
                if (ruleInfo.ruleDirection != duplicateRuleBeginIterator->ruleDirection)
                {
                    continue;
                }
                if (!RuleNamesMatch(ruleInfo.ruleName, duplicateRuleBeginIterator->ruleName))
                {
                    continue;
                }
                if (!RuleNamesMatch(ruleInfo.ruleDescription, duplicateRuleBeginIterator->ruleDescription))
                {
                    continue;
                }
                // PrintRuleInformation(ruleInfo);

                matchingAppIsolationValues.emplace_back(registryValue);
                ++appIsolationRegistryMatches;
            }
            wprintf(L"\t>> total App-Isolation registry matches: %u\n", appIsolationRegistryMatches);
            for (const auto& value : matchingAppIsolationValues)
            {
                wprintf(L"\t     %ws\n", value.c_str());
            }
            wprintf(L"\n");
        }

        if (g_DeleteDuplicates)
        {
            {
                const auto promptBeforeDeleting = g_MatchType == MatchType::LooseMatch;
                DeleteDuplicateRulesViaCom(
                    promptBeforeDeleting,
                    firewallRules.get(),
                    INetFwNormalizedRules,
                    duplicateRuleBeginIterator,
                    duplicateRuleEndIterator);
            }
        }
    }
    const auto timeToProcess = timer.end();

    if (g_MatchType == MatchType::LooseMatch)
    {
        wprintf(
            L"\nResults from analyzing Firewall rules that match only rule key fields (e.g. not comparing name and description fields):\n");
    }
    else
    {
        wprintf(L"\nResults from analyzing Firewall rules that exactly match all rule fields:\n");
    }

    wprintf(
        L"\tTotal Firewall rules processed: %llu\n"
        L"\tUnique firewall rules with duplicates: %llu\n"
        L"\tTotal of all the different duplicate Firewall rules: %llu\n",
        INetFwNormalizedRules.size(),
        totalRulesWithDuplicates,
        sumOfAllDuplicateRules);

    if (g_PrintDebugInfo)
    {
        wprintf(L"\n");
        if (!g_DeleteDuplicates)
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
    }
}
catch (const std::exception& e)
{
    wprintf(L"\nERROR: %hs\n", e.what());
    return -1;
}
