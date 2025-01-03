#pragma once

#include <string>

#include <Windows.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/resource.h>

struct NormalizedFirewallRule
{
    wil::com_ptr<INetFwRule3> rule;
    wil::unique_bstr ruleName;
    wil::unique_bstr ruleDescription;
    wil::unique_bstr ruleGrouping;
    NET_FW_RULE_DIRECTION ruleDirection{};
    NET_FW_ACTION ruleAction{};
    LONG ruleProfiles{};

    std::wstring ruleOwnerUsername;
    DWORD errorRetrievingOwnerUsername{};

    std::wstring normalizedRuleDetails;
    bool normalizedRuleDetailsContainsNonAsciiString = false;
    bool temporarilyRenamed = false;
    bool ruleEnabled = false;

    // guarantee this object is never copied, only moved
    NormalizedFirewallRule(const NormalizedFirewallRule&) = delete;
    NormalizedFirewallRule& operator=(const NormalizedFirewallRule&) = delete;

    NormalizedFirewallRule(NormalizedFirewallRule&&) noexcept = default;
    NormalizedFirewallRule& operator=(NormalizedFirewallRule&&) noexcept = default;

    NormalizedFirewallRule() = default;
    ~NormalizedFirewallRule() = default;

    // the wstring is required to already be lower-cased
    void AppendValueLowerCase(const std::wstring& value)
    {
        normalizedRuleDetails.append(value);
    }

    void AppendValue(const BSTR value)
    {
        if (value && value[0] != L'\0')
        {
            // if is an ASCII character (ANSI code page) then can trivially convert to lower-case
            // and can avoid a more expensive call to CompareStringOrdinal
            for (wchar_t* nextCharacter = value; *nextCharacter != '\0';)
            {
                if (iswascii(*nextCharacter))
                {
                    // towlower only works on ASCII characters
                    *nextCharacter = towlower(*nextCharacter);
                }
                else
                {
                    // if hit any non-ascii character, just break from the loop
                    normalizedRuleDetailsContainsNonAsciiString = true;
                    break;
                }
                ++nextCharacter;
            }
            normalizedRuleDetails.append(value);
        }
    }

    // the one VARIANT that's returned from the Firewall Rule interface
    // is for an array of strings for Interfaces
    void AppendValue(const wil::unique_variant& value)
    {
        if (value.vt == VT_EMPTY)
        {
            // it's acceptable to be either EMPTY
            // or an ARRAY of VARIANT's
            return;
        }
        if (value.vt != (VT_ARRAY | VT_VARIANT))
        {
            THROW_HR(E_UNEXPECTED);
        }

        const auto arrayDimensions = SafeArrayGetDim(value.parray);
        for (UINT i = 0; i < arrayDimensions; ++i)
        {
            LONG lBound{}; // lower bound
            THROW_IF_FAILED(SafeArrayGetLBound(value.parray, i + 1, &lBound));
            LONG uBound{}; // upper bound
            THROW_IF_FAILED(SafeArrayGetUBound(value.parray, i + 1, &uBound));

            for (LONG j = lBound; j <= uBound; ++j)
            {
                wil::unique_variant element{};
                THROW_IF_FAILED(SafeArrayGetElement(value.parray, &j, &element));

                if (element.vt != VT_BSTR)
                {
                    THROW_HR(E_UNEXPECTED);
                }

                if (element.bstrVal && element.bstrVal[0] != L'\0')
                {
                    AppendValue(element.bstrVal);
                }
            }
        }
    }

    template <typename T>
    void AppendValue(T t)
    {
        // ensure conversion from the type provided by the caller
        const int32_t convertedValue{t};
        if (convertedValue != 0)
        {
            normalizedRuleDetails.append(std::to_wstring(convertedValue));
        }
    }
};

inline void PrintNormalizedFirewallRule(const NormalizedFirewallRule& ruleInfo) noexcept
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

// appx-created rules start with:
// @{
// and contain the resource id string:
// ms-resource://
// these are not managed by the public COM API, unfortunately
inline bool IsRuleAnAppxRule(const std::wstring& ruleName)
{
    //18 == length of '@{' (2) + length of 'ms-resource://' (14)
    if (ruleName.length() < 16)
    {
        return false;
    }
    if (ruleName[0] != L'@' || ruleName[1] != '{')
    {
        return false;
    }

    // now search for ms-resource://  --- this is case-sensitive, but that seems correct for APPX rules
    constexpr auto* appxResourceStringId = L"ms-resource://";
    return ruleName.find(appxResourceStringId) != std::wstring::npos;
}

inline bool IsRuleAnAppxRule(const NormalizedFirewallRule& ruleInfo)
{
    if (!ruleInfo.ruleName.is_valid())
    {
        return false;
    }

    const auto bstrString = ruleInfo.ruleName.get();
    return IsRuleAnAppxRule(bstrString);
}


inline bool RuleNamesMatch(const wil::unique_bstr& lhs, const wil::unique_bstr& rhs) noexcept
{
    // checking the string length of a BSTR is very cheap - it just reads the length field in the bstr
    // (the 32 bits allocated right before the start of the string)
    const auto lhs_length = SysStringLen(lhs.get());
    const auto rhs_length = SysStringLen(rhs.get());
    if (lhs_length != rhs_length)
    {
        return false;
    }

    constexpr BOOL bIgnoreCase = TRUE;
    const auto ruleNamesMatch = CompareStringOrdinal(
        lhs.get(),
        static_cast<int>(lhs_length),
        rhs.get(),
        static_cast<int>(rhs_length),
        bIgnoreCase);
    return ruleNamesMatch == CSTR_EQUAL;
}

inline bool RulesMatchExactly(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
    constexpr BOOL bIgnoreCase = TRUE;

    if (lhs.normalizedRuleDetails.size() != rhs.normalizedRuleDetails.size())
    {
        return false;
    }

    // checking the string length of a BSTR is very cheap - it just reads the length field in the bstr
    // (the 32 bits allocated right before the start of the string)
    if (SysStringLen(lhs.ruleName.get()) != SysStringLen(rhs.ruleName.get()))
    {
        return false;
    }
    if (SysStringLen(lhs.ruleDescription.get()) != SysStringLen(rhs.ruleDescription.get()))
    {
        return false;
    }

    const auto ruleNamesMatch = CompareStringOrdinal(
        lhs.ruleName.get(),
        -1,
        rhs.ruleName.get(),
        -1,
        bIgnoreCase);
    if (ruleNamesMatch != CSTR_EQUAL)
    {
        return false;
    }

    const auto ruleDescriptionsMatch = CompareStringOrdinal(
        lhs.ruleDescription.get(),
        -1,
        rhs.ruleDescription.get(),
        -1,
        bIgnoreCase);
    if (ruleDescriptionsMatch != CSTR_EQUAL)
    {
        return false;
    }

    // if all ascii characters, can just do a raw memcmp without any conversions
    if (!lhs.normalizedRuleDetailsContainsNonAsciiString && !rhs.normalizedRuleDetailsContainsNonAsciiString)
    {
        return memcmp(
            lhs.normalizedRuleDetails.c_str(),
            rhs.normalizedRuleDetails.c_str(),
            lhs.normalizedRuleDetails.size() * sizeof(wchar_t)) == 0;
    }

    const auto ruleDetailsMatch = CompareStringOrdinal(
        lhs.normalizedRuleDetails.c_str(),
        static_cast<int>(lhs.normalizedRuleDetails.size()),
        rhs.normalizedRuleDetails.c_str(),
        static_cast<int>(rhs.normalizedRuleDetails.size()),
        bIgnoreCase);
    return ruleDetailsMatch == CSTR_EQUAL;
}

inline bool RuleDetailsMatch(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
    constexpr BOOL bIgnoreCase = TRUE;

    if (lhs.normalizedRuleDetails.size() != rhs.normalizedRuleDetails.size())
    {
        return false;
    }
    // if all ascii characters, can just do a raw memcmp without any conversions
    if (!lhs.normalizedRuleDetailsContainsNonAsciiString && !rhs.normalizedRuleDetailsContainsNonAsciiString)
    {
        return memcmp(
            lhs.normalizedRuleDetails.c_str(),
            rhs.normalizedRuleDetails.c_str(),
            lhs.normalizedRuleDetails.size() * sizeof(wchar_t)) == 0;
    }

    const auto ruleDetailsMatch = CompareStringOrdinal(
        lhs.normalizedRuleDetails.c_str(),
        static_cast<int>(lhs.normalizedRuleDetails.size()),
        rhs.normalizedRuleDetails.c_str(),
        static_cast<int>(rhs.normalizedRuleDetails.size()),
        bIgnoreCase);
    return ruleDetailsMatch == CSTR_EQUAL;
}

inline bool SortExactMatches(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
    constexpr BOOL bIgnoreCase = TRUE;

    if (lhs.normalizedRuleDetails.size() != rhs.normalizedRuleDetails.size())
    {
        return lhs.normalizedRuleDetails.size() < rhs.normalizedRuleDetails.size();
    }

    const auto ruleNamesMatch = CompareStringOrdinal(
        lhs.ruleName.get(),
        -1,
        rhs.ruleName.get(),
        -1,
        bIgnoreCase);
    if (ruleNamesMatch != CSTR_EQUAL)
    {
        return CSTR_LESS_THAN == ruleNamesMatch;
    }

    const auto ruleDescriptionsMatch = CompareStringOrdinal(
        lhs.ruleDescription.get(),
        -1,
        rhs.ruleDescription.get(),
        -1,
        bIgnoreCase);
    if (ruleDescriptionsMatch != CSTR_EQUAL)
    {
        return CSTR_LESS_THAN == ruleDescriptionsMatch;
    }

    const auto normalizedRulesMatch = CompareStringOrdinal(
        lhs.normalizedRuleDetails.c_str(),
        static_cast<int>(lhs.normalizedRuleDetails.size()),
        rhs.normalizedRuleDetails.c_str(),
        static_cast<int>(rhs.normalizedRuleDetails.size()),
        bIgnoreCase);
    if (normalizedRulesMatch != CSTR_EQUAL)
    {
        return CSTR_LESS_THAN == normalizedRulesMatch;
    }

    // if everything matches, then sort by rules that are enabled before rules that are disabled
    if (lhs.ruleEnabled && !rhs.ruleEnabled)
    {
        return true;
    }
    return false;
}

inline bool SortOnlyMatchingDetails(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
    constexpr BOOL bIgnoreCase = TRUE;

    if (lhs.normalizedRuleDetails.size() != rhs.normalizedRuleDetails.size())
    {
        return lhs.normalizedRuleDetails.size() < rhs.normalizedRuleDetails.size();
    }

    const auto ruleNamesMatch = CompareStringOrdinal(
        lhs.ruleName.get(),
        -1,
        rhs.ruleName.get(),
        -1,
        bIgnoreCase);
    if (ruleNamesMatch != CSTR_EQUAL)
    {
        return CSTR_LESS_THAN == ruleNamesMatch;
    }

    const auto ruleDescriptionsMatch = CompareStringOrdinal(
        lhs.ruleDescription.get(),
        -1,
        rhs.ruleDescription.get(),
        -1,
        bIgnoreCase);
    if (ruleDescriptionsMatch != CSTR_EQUAL)
    {
        return CSTR_LESS_THAN == ruleDescriptionsMatch;
    }

    const auto normalizedRulesMatch = CompareStringOrdinal(
        lhs.normalizedRuleDetails.c_str(),
        static_cast<int>(lhs.normalizedRuleDetails.size()),
        rhs.normalizedRuleDetails.c_str(),
        static_cast<int>(rhs.normalizedRuleDetails.size()),
        bIgnoreCase);
    if (normalizedRulesMatch != CSTR_EQUAL)
    {
        return CSTR_LESS_THAN == normalizedRulesMatch;
    }

    // if everything matches, then sort by rules that are enabled before rules that are disabled
    if (lhs.ruleEnabled && !rhs.ruleEnabled)
    {
        return true;
    }
    return false;
}
