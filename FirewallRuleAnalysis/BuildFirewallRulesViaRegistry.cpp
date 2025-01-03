#include <algorithm>
#include <cwctype>
#include <functional>
#include <string>
#include <vector>

#include <windows.h>
#include <netfw.h>

#include <wil/stl.h>
#include <wil/com.h>
#include <wil/registry.h>

#include "BuildFirewallRulesViaRegistry.h"
#include "NormalizedFirewallRule.h"

constexpr auto* LocalFirewallRulePath =
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
constexpr auto* AppIsoFirewallRulePath =
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules";

struct RegistryToComMapping
{
    const std::vector<const wchar_t*> registryKeywords;
    const wchar_t* matchingComMethod = nullptr;
    const uint32_t maxOccurrences = 0;
    const std::function<void(const std::wstring&, NormalizedFirewallRule&)> valueToRuleInfoFn = nullptr;
    uint32_t numOccurrences{0};
};

// returns the [registry value name],[parsed rule name]
std::vector<std::tuple<std::wstring, NormalizedFirewallRule>> BuildFirewallRuleInfo(FirewallRuleRegistryStore store)
{
    std::vector<std::tuple<std::wstring, NormalizedFirewallRule>> returnValues;
    wil::unique_hkey localRuleKey;
    switch (store)
    {
    case FirewallRuleRegistryStore::Local:
        {
            localRuleKey = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, LocalFirewallRulePath);
            break;
        }
    case FirewallRuleRegistryStore::AppIsolation:
        {
            localRuleKey = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, AppIsoFirewallRulePath);
            break;
        }
    }

    // TODO: make a wil::reg::make_range_value, etc. so callers don't have to do this stuff
    for (const auto& value_data : wil::make_range(wil::reg::value_iterator{localRuleKey.get()},
                                                  wil::reg::value_iterator{}))
    {
        if (value_data.type != REG_SZ)
        {
            wprintf(L"***** Broken registry value -- type is not REG_SZ : %d *****\n", value_data.type);
            DebugBreak();
            return {};
        }

        // ruleValue cannot be const since we will eventually need modify-able iterators into this string
        auto ruleValue = wil::reg::get_value_string(localRuleKey.get(), value_data.name.c_str());

        NormalizedFirewallRule ruleInfo{};

        // ReSharper disable StringLiteralTypo
        RegistryToComMapping registryToComMapping[]
        {
            {
                {L"name"}, L"get_Name", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.ruleName = wil::make_bstr(value.c_str());
                }
            },
            {
                {L"desc"}, L"get_Description", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.ruleDescription = wil::make_bstr(value.c_str());
                }
            },
            {
                {L"embedctxt"}, L"get_Grouping", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.ruleGrouping = wil::make_bstr(value.c_str());
                    ruleInfo.AppendValue(ruleInfo.ruleGrouping.get());
                }
            },
            {
                {L"active"}, L"get_Enabled", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_Enabled returns a VARIANT_BOOL - must be either TRUE or FALSE
                    bool valid = false;
                    if (value.size() == 4)
                    {
                        if (wmemcmp(value.c_str(), L"true", 4) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(1);
                        }
                    }
                    else if (value.size() == 5)
                    {
                        if (wmemcmp(value.c_str(), L"false", 5) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(0);
                        }
                    }

                    if (!valid)
                    {
                        wprintf(L"***** Broken registry value -- active should be TRUE or FALSE : %ws *****\n",
                                value.c_str());
                        DebugBreak();
                    }
                }
            },
            {
                {L"action"}, L"get_Action", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_Enabled returns a NET_FW_ACTION - Block is 0, Allow is 1
                    bool valid = false;
                    if (value.size() == 5)
                    {
                        if (wmemcmp(value.c_str(), L"block", 5) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(0);
                        }
                        else if (wmemcmp(value.c_str(), L"allow", 5) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(1);
                        }
                    }

                    if (!valid)
                    {
                        wprintf(L"***** Broken registry value -- action should be ALLOW or BLOCK : %ws *****\n",
                                value.c_str());
                        DebugBreak();
                    }
                }
            },
            {
                {L"dir"}, L"get_Direction", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_Direction returns NET_FW_RULE_DIRECTION: In is 1, Out is 2
                    bool valid = false;
                    if (value.size() == 2)
                    {
                        if (wmemcmp(value.c_str(), L"in", 2) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(1);
                        }
                    }
                    else if (value.size() == 3)
                    {
                        if (wmemcmp(value.c_str(), L"out", 3) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(2);
                        }
                    }

                    if (!valid)
                    {
                        wprintf(L"***** Broken registry value -- action should be ALLOW or BLOCK : %ws *****\n",
                                value.c_str());
                        DebugBreak();
                    }
                }
            },
            {
                {L"protocol"}, L"get_Protocol", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_Protocol returns a LONG
                    // throws if not a valid long number
                    ruleInfo.AppendValue(std::stol(value));
                }
            },
            {
                {L"profile"}, L"get_Profiles", 3, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_Profiles returns a LONG that is the OR combination of NET_FW_PROFILE_TYPE2 enums
                    // must be =Private, =Public, =Domain
                    bool valid = false;
                    if (value.size() == 6 && (0 == wmemcmp(value.c_str(), L"public", 6)))
                    {
                        valid = true;
                        ruleInfo.ruleProfiles |= NET_FW_PROFILE2_PUBLIC;
                    }
                    else if (value.size() == 7 && (0 == wmemcmp(value.c_str(), L"private", 7)))
                    {
                        valid = true;
                        ruleInfo.ruleProfiles |= NET_FW_PROFILE2_PRIVATE;
                    }
                    else if (value.size() == 6 && (0 == wmemcmp(value.c_str(), L"domain", 6)))
                    {
                        valid = true;
                        ruleInfo.ruleProfiles |= NET_FW_PROFILE2_DOMAIN;
                    }

                    if (!valid)
                    {
                        wprintf(
                            L"***** Broken registry value -- profile should be PUBLIC, PRIVATE, or DOMAIN : %ws *****\n",
                            value.c_str());
                        DebugBreak();
                    }
                }
            },
            {
                {L"luown"}, L"get_LocalUserOwner", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.AppendValueLowerCase(value);
                }
            },
            {
                {L"luauth", L"luauth2_24"}, L"get_LocalUserAuthorizedList", 1,
                [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.AppendValueLowerCase(value);
                }
            },
            {
                {L"app"}, L"get_ApplicationName", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.AppendValueLowerCase(value);
                }
            },
            {
                {L"apppkgid"}, L"get_LocalAppPackageId", 1,
                [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.AppendValueLowerCase(value);
                }
            },
            {
                {L"svc"}, L"get_ServiceName", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    ruleInfo.AppendValueLowerCase(value);
                }
            },
            {
                {L"edge"}, L"get_EdgeTraversal", 1, [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_EdgeTraversal returns a VARIANT_BOOL - must be either TRUE or FALSE
                    bool valid = false;
                    if (value.size() == 4)
                    {
                        if (wmemcmp(value.c_str(), L"true", 4) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(1);
                        }
                    }
                    else if (value.size() == 5)
                    {
                        if (wmemcmp(value.c_str(), L"false", 5) == 0)
                        {
                            valid = true;
                            ruleInfo.AppendValue(0);
                        }
                    }

                    if (!valid)
                    {
                        wprintf(L"***** Broken registry value -- edge should be TRUE or FALSE : %ws *****\n",
                                value.c_str());
                        DebugBreak();
                    }
                }
            },
            {
                {L"defer"}, L"get_EdgeTraversalOptions", 1,
                [](const std::wstring& value, NormalizedFirewallRule& ruleInfo)
                {
                    // get_EdgeTraversalOptions returns a LONG 
                    // throws if not a valid long number
                    ruleInfo.AppendValue(std::stol(value));
                }
            },
            {
                {L"if"}, L"get_Interfaces", INFINITE, [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"iftype", L"iftype2_23"}, L"get_InterfaceTypes", INFINITE,
                [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"la4", L"la6"}, L"get_LocalAddresses", INFINITE, [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"ra4", L"ra42", L"ra43", L"ra6", L"ra62", L"ra63"}, L"get_RemoteAddresses", INFINITE,
                [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"lport", L"lport2_10", L"lport2_20", L"lport2_24", L"lport2_29"}, L"get_LocalPorts", INFINITE, [
                ](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"rport", L"rport2_10", L"rport2_25"}, L"get_RemotePorts", INFINITE,
                [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"icmp4", L"icmp6"}, L"get_IcmpTypesAndCodes", INFINITE,
                [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"ruauth"}, L"get_RemoteUserAuthorizedList", INFINITE, [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"rmauth"}, L"get_RemoteMachineAuthorizedList", INFINITE,
                [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            {
                {L"security", L"security2", L"security2_9"}, L"get_SecureFlags", INFINITE,
                [](const std::wstring&, NormalizedFirewallRule&)
                {
                    // TODO
                }
            },
            // firewall registry value rule fields that don't map to the public COM API
            {{L"radynkey"}},
            {{L"platform"}},
            {{L"platform2"}},
            {{L"securityrealmid"}},
            {{L"autogenipsec"}},
            {{L"lsm"}},
            {{L"lom"}},
            {{L"authbypassout"}},
            {{L"skipver"}},
            {{L"pcross"}},
            {{L"ttk", L"ttk2_22", L"ttk2_27", L"ttk2_28"}},
            {{L"pfn"}},
            {{L"nnm"}},
            {{L"btoif"}},
            {{L"sytesmosonly"}},
            {{L"gameosonly"}},
            {{L"devmode"}},
            {{L"rsnm"}},
            {{L"rsnmE"}},
            {{L"rsnmN"}},
            {{L"fqbn"}},
            {{L"comptid"}},
            {{L"caudit"}},
            {{L"applb"}},
        };
        // ReSharper restore StringLiteralTypo

        // walk the returned string looking for |keyword=value|
        // wprintf(L"Parsing the registry value : %ws\n", ruleValue.c_str());

        const auto endingIterator = ruleValue.end();
        auto stringIterator = ruleValue.begin();
        while (stringIterator != endingIterator)
        {
            // find the next keyword
            stringIterator = std::find(stringIterator, endingIterator, L'|');
            if (stringIterator == endingIterator)
            {
                continue;
            }

            ++stringIterator; // move to the character following the '|'
            // the registry value string ends in a '|' -- check if we are at the end
            if (stringIterator == endingIterator)
            {
                break;
            }

            // now we know the begin() of the next keyword
            const auto startOfKeyword = stringIterator;

            // find the next value
            stringIterator = std::find(stringIterator, endingIterator, L'=');
            if (stringIterator == endingIterator)
            {
                wprintf(L"***** Broken registry value -- empty Keyword string : %ws *****\n",
                        std::wstring(startOfKeyword, endingIterator).c_str());
                DebugBreak();
                return {};
            }

            // now we know the end() of the keyword, at the '='
            auto endOfKeyword = stringIterator;
            if (endOfKeyword - startOfKeyword == 1)
            {
                wprintf(L"***** Broken registry value -- the string length of Value is zero : %ws *****\n",
                        std::wstring(startOfKeyword, endingIterator).c_str());
                DebugBreak();
                return {};
            }

            ++stringIterator; // move to the character following the '='

            // now we know the begin() of the next value
            const auto startOfValue = stringIterator;

            // verify there's not a | between the start of they keyword and the '=' that we just found
            // i.e., we expect |keyword=value|, with no | in 'keyword'
            // that would indicate a busted registry value
            if (std::find(startOfKeyword, startOfValue, L'|') != startOfValue)
            {
                wprintf(L"***** Broken registry value -- invalid Keyword=Value string : %ws *****\n",
                        std::wstring(startOfKeyword, endingIterator).c_str());
                DebugBreak();
                return {};
            }

            stringIterator = std::find(stringIterator, endingIterator, L'|');
            // now we know the end() of the next keyword
            auto endOfValue = stringIterator;
            if (endOfValue - startOfValue == 0)
            {
                wprintf(L"***** Broken registry value -- empty Value string : %ws *****\n",
                        std::wstring(startOfKeyword, endingIterator).c_str());
                DebugBreak();
                return {};
            }

            // leave stringIterator referencing the last | character
            // since that will be the start of the key/value pair for the next loop iteration

            // now find the matching keyword
            auto compareKeywords = [](const std::wstring::iterator& registryKeywordBegin,
                                      const std::wstring::iterator& registryKeywordEnd, PCWSTR keyword) -> bool
            {
                const size_t lhs_length = registryKeywordEnd - registryKeywordBegin;
                const size_t rhs_length = wcslen(keyword);
                if (lhs_length != rhs_length)
                {
                    return false;
                }

                // this may look odd - it's taking the address of the character pointed to by registryKeywordBegin
                return 0 == wmemcmp(&(registryKeywordBegin.operator*()), keyword, lhs_length);
            };

            // keywords must be alpha characters -- make them lower-case so we can memcmp
            for (auto iterateKeyword = startOfKeyword; iterateKeyword != endOfKeyword; ++iterateKeyword)
            {
                if (std::iswalpha(*iterateKeyword))
                {
                    *iterateKeyword = std::towlower(*iterateKeyword);
                }
                else if (std::iswdigit(*iterateKeyword) || *iterateKeyword == L'_')
                {
                    // digits are OK for some keywords
                }
                else
                {
                    wprintf(L"***** Broken registry value -- invalid Keyword string : %ws *****\n",
                            std::wstring(startOfKeyword, endOfKeyword).c_str());
                    DebugBreak();
                    return {};
                }
            }

            bool foundMapping = false;
            for (auto& mapping : registryToComMapping)
            {
                for (const auto& keyword : mapping.registryKeywords)
                {
                    if (compareKeywords(startOfKeyword, endOfKeyword, keyword))
                    {
                        foundMapping = true;
                    }

                    if (foundMapping)
                    {
                        break;
                    }
                }

                if (foundMapping)
                {
                    if (mapping.matchingComMethod)
                    {
                        ++mapping.numOccurrences;
                        if (mapping.numOccurrences > mapping.maxOccurrences)
                        {
                            wprintf(L"***** Broken registry value -- repeated Keyword string : %ws *****\n",
                                    std::wstring(startOfKeyword, endOfKeyword).c_str());
                            DebugBreak();
                            return {};
                        }
                    }

                    // attempt to map value characters back to lower-case
                    // this will work for system-managed strings
                    for (auto iterateValue = startOfValue; iterateValue != endOfValue; ++iterateValue)
                    {
                        if (std::iswalpha(*iterateValue))
                        {
                            *iterateValue = std::towlower(*iterateValue);
                        }
                    }

                    if (mapping.valueToRuleInfoFn)
                    {
                        mapping.valueToRuleInfoFn(std::wstring(startOfValue, endOfValue), ruleInfo);
                    }
                    break;
                }
            }

            if (!foundMapping)
            {
                wprintf(L"***** Broken registry value -- unknown Keyword string : %ws *****\n",
                        std::wstring(startOfKeyword, endOfKeyword).c_str());
                DebugBreak();
                return {};
            }
        }

        returnValues.emplace_back(std::make_tuple(std::move(ruleValue), std::move(ruleInfo)));
    }

    std::ranges::sort(returnValues,
                      [](const std::tuple<std::wstring, NormalizedFirewallRule>& lhs,
                         const std::tuple<std::wstring, NormalizedFirewallRule>& rhs)
                      {
                          // just sort on the string read from the registry
                          return std::get<0>(lhs) < std::get<0>(rhs);
                      });
    return returnValues;
}

size_t CountDuplicateFirewallRules(
    const std::vector<std::tuple<std::wstring, NormalizedFirewallRule>>& registryFirewallRules)
{
    size_t totalRulesWithDuplicates{0};

    for (auto currentIterator = registryFirewallRules.begin();;)
    {
        // the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
        const auto duplicateRuleBeginIterator{
            std::adjacent_find(
                currentIterator,
                registryFirewallRules.end(),
                [](const std::tuple<std::wstring, NormalizedFirewallRule>& lhs,
                   const std::tuple<std::wstring, NormalizedFirewallRule>& rhs)
                {
                    return std::get<0>(lhs) == std::get<0>(rhs);
                })
        };
        if (duplicateRuleBeginIterator == registryFirewallRules.cend())
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
        while (currentIterator != registryFirewallRules.end())
        {
            if (currentIterator + 1 == registryFirewallRules.end())
            {
                break;
            }
            // iterate through localRegistryFirewallRules until we hit the end of the vector or until the strings comparison returns false
            // i.e., we found the iterator past the last duplicate
            if (std::get<0>(*currentIterator) != std::get<0>(*(currentIterator + 1)))
            {
                break;
            }
            ++currentIterator;
        }
        // the loop breaks when currentIterator matches currentIterator + 1, or when hitting the end
        // incrementing currentIterator so it points to next-rule-past the one that matched
        if (currentIterator != registryFirewallRules.end())
        {
            ++currentIterator;
        }

        // this should never happen since adjacent_find identified at least 2 rules that match
        FAIL_FAST_IF(currentIterator == duplicateRuleBeginIterator);
        wprintf(
            L"    (%llu duplicates) %ws\n",
            currentIterator - duplicateRuleBeginIterator,
            std::get<0>(*duplicateRuleBeginIterator).c_str());
    }

    return totalRulesWithDuplicates;
}
