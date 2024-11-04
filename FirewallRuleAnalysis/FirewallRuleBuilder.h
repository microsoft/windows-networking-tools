#pragma once
#include <optional>
#include <regex>
#include <string>

#include <Windows.h>
#include <netfw.h>
#include <sddl.h>

#include <wil/com.h>
#include <wil/resource.h>

struct NormalizedRuleInfo
{
	wil::com_ptr<INetFwRule3> rule;
	wil::unique_bstr ruleName;
	wil::unique_bstr ruleDescription;
	NET_FW_RULE_DIRECTION ruleDirection;

	std::wstring ruleOwnerUsername;
	DWORD errorRetrievingOwnerUsername{};

	std::wstring normalizedRuleDetails;
	bool normalizedRuleDetailsContainsNonAsciiString = false;
	bool temporarilyRenamed = false;
	bool ruleEnabled = false;

	// guarantee this object is never copied, only moved
	NormalizedRuleInfo(const NormalizedRuleInfo&) = delete;
	NormalizedRuleInfo& operator=(const NormalizedRuleInfo&) = delete;

	NormalizedRuleInfo(NormalizedRuleInfo&&) noexcept = default;
	NormalizedRuleInfo& operator=(NormalizedRuleInfo&&) noexcept = default;

	NormalizedRuleInfo() = default;
	~NormalizedRuleInfo() = default;

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
		const int32_t convertedValue{ t };
		if (convertedValue != 0)
		{
			normalizedRuleDetails.append(std::to_wstring(convertedValue));
		}
	}
};

inline uint32_t RuleDetailsDeepMatchComparisonCount = 0;

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
inline bool IsRuleAnAppxRule(const NormalizedRuleInfo& ruleInfo)
{
	if (!ruleInfo.ruleName.is_valid())
	{
		return false;
	}

	const auto bstrString = ruleInfo.ruleName.get();
	return IsRuleAnAppxRule(bstrString);
}

inline std::tuple<DWORD, std::wstring> ConvertSidStringToUserName(_In_ PCWSTR localUserOwner)
{
	DWORD errorRetrievingOwnerUsername{};
	std::wstring ruleOwnerUsername{};

	wil::unique_any_psid convertedSid;
	if (ConvertStringSidToSidW(localUserOwner, &convertedSid))
	{
		DWORD nameLength{};
		DWORD referencedDomainNameLength{};
		SID_NAME_USE sidNameUse{};
		LookupAccountSidW(
			nullptr, // lookup on the local system
			convertedSid.get(),
			nullptr,
			&nameLength,
			nullptr,
			&referencedDomainNameLength,
			&sidNameUse);
		if (nameLength == 0)
		{
			errorRetrievingOwnerUsername = GetLastError();
		}
		else
		{
			ruleOwnerUsername.resize(nameLength);

			std::wstring referencedDomainNameString;
			if (referencedDomainNameLength > 0)
			{
				referencedDomainNameString.resize(referencedDomainNameLength);
			}
			if (!LookupAccountSidW(
				nullptr, // lookup on the local system
				convertedSid.get(),
				ruleOwnerUsername.data(),
				&nameLength,
				referencedDomainNameLength > 0 ? referencedDomainNameString.data() : nullptr,
				&referencedDomainNameLength,
				&sidNameUse))
			{
				errorRetrievingOwnerUsername = GetLastError();
			}
			else
			{
				// remove the embedded null-terminators from the std::wstring objects
				ruleOwnerUsername.resize(ruleOwnerUsername.size() - 1);
				if (referencedDomainNameLength > 0)
				{
					referencedDomainNameString.resize(referencedDomainNameString.size() - 1);
				}

				if (!referencedDomainNameString.empty())
				{
					std::wstring fullOwnerName{ std::move(referencedDomainNameString) };
					fullOwnerName.append(L"\\");
					fullOwnerName.append(ruleOwnerUsername);
					ruleOwnerUsername = std::move(fullOwnerName);
				}
			}
		}
	}

	return { errorRetrievingOwnerUsername, ruleOwnerUsername };
}

enum class FirewallRuleStore
{
	Local,
	AppIso
};
constexpr auto* LocalFirewallRulePath = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
constexpr auto* AppIsoFirewallRulePath = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules";

// returns the [registry value name],[parsed rule name]
inline std::vector<std::tuple<std::wstring, NormalizedRuleInfo>> ReadRegistryRules(FirewallRuleStore store)
{
	// the regex to read the name field out of the registry where rules are written. e.g.
	// v2.33|Action=Allow|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.WindowsCalculator_11.2409.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCalculator/Resources/AppStoreName}|Desc=@{Microsoft.WindowsCalculator_11.2409.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCalculator/Resources/AppStoreName}|PFN=Microsoft.WindowsCalculator_8wekyb3d8bbwe|LUOwn=S-1-12-1-910410835-1306523740-2996082354-1245529378|EmbedCtxt=@{Microsoft.WindowsCalculator_11.2409.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCalculator/Resources/AppStoreName}|Platform=2:6:2|Platform2=GTEQ|
	const std::wregex findNameInRegistryValue(L".*?\\|Name=(.*?)\\|", std::regex_constants::ECMAScript | std::regex_constants::optimize);
	const std::wregex findDescriptionInRegistryValue(L".*?\\|Desc=(.*?)\\|", std::regex_constants::ECMAScript | std::regex_constants::optimize);
	const std::wregex findDirectionInRegistryValue(L".*?\\|Dir=(.*?)\\|", std::regex_constants::ECMAScript | std::regex_constants::optimize);
	const std::wregex findEnabledInRegistryValue(L".*?\\|Active=(.*?)\\|", std::regex_constants::ECMAScript | std::regex_constants::optimize);
	const std::wregex findUserOwnerInRegistryValue(L".*?\\|LUOwn=(.*?)\\|", std::regex_constants::ECMAScript | std::regex_constants::optimize);

	std::vector<std::tuple<std::wstring, NormalizedRuleInfo>> returnValues;
	wil::unique_hkey localRuleKey;
	switch (store)
	{
	case FirewallRuleStore::Local:
	{
		localRuleKey = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, LocalFirewallRulePath);
		break;
	}
	case FirewallRuleStore::AppIso:
	{
		localRuleKey = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, AppIsoFirewallRulePath);
		break;
	}
	}
	for (const auto& value_data : wil::make_range(wil::reg::value_iterator{ localRuleKey.get() }, wil::reg::value_iterator{}))
	{
		if (value_data.type != REG_SZ)
		{
			DebugBreak();
		}

		NormalizedRuleInfo ruleInfo{};
		const auto ruleValue = wil::reg::get_value_string(localRuleKey.get(), value_data.name.c_str());

		// ruleName
		if (std::wcmatch matchResults; std::regex_search(ruleValue.c_str(), matchResults, findNameInRegistryValue))
		{
			/*
			 * For debugging the regex:
			wprintf(L"\t REGEX RESULTS (%lld):\n", matchResults.size());
			wprintf(L"\t\t[0] %ws\n", matchResults[0].str().c_str());
			wprintf(L"\t\t[1] %ws\n", matchResults[1].str().c_str());
			*/
			ruleInfo.ruleName = wil::make_bstr(matchResults[1].str().c_str());
		}
		else
		{
			DebugBreak();
		}

		// ruleDescription
		if (std::wcmatch matchResults; std::regex_search(ruleValue.c_str(), matchResults, findDescriptionInRegistryValue))
		{
			ruleInfo.ruleDescription = wil::make_bstr(matchResults[1].str().c_str());
		}

		// ruleDirection
		if (std::wcmatch matchResults; std::regex_search(ruleValue.c_str(), matchResults, findDirectionInRegistryValue))
		{
			if (matchResults[1].str() == L"In")
			{
				ruleInfo.ruleDirection = NET_FW_RULE_DIR_IN;
			}
			else if (matchResults[1].str() == L"Out")
			{
				ruleInfo.ruleDirection = NET_FW_RULE_DIR_OUT;
			}
			else
			{
				DebugBreak();
			}
		}
		else
		{
			DebugBreak();
		}

		// ruleEnabled
		if (std::wcmatch matchResults; std::regex_search(ruleValue.c_str(), matchResults, findEnabledInRegistryValue))
		{
			if (matchResults[1].str() == L"TRUE")
			{
				ruleInfo.ruleEnabled = true;
			}
			else if (matchResults[1].str() == L"FALSE")
			{
				ruleInfo.ruleEnabled = false;
			}
			else
			{
				DebugBreak();
			}
		}
		else
		{
			DebugBreak();
		}

		// ruleEnabled
		if (std::wcmatch matchResults; std::regex_search(ruleValue.c_str(), matchResults, findUserOwnerInRegistryValue))
		{
			const auto localUserOwner = matchResults[1].str();
			const auto userConversion = ConvertSidStringToUserName(localUserOwner.c_str());
			ruleInfo.errorRetrievingOwnerUsername = std::get<0>(userConversion);
			ruleInfo.ruleOwnerUsername = std::get<1>(userConversion);
			/*
			if (ruleInfo.errorRetrievingOwnerUsername != NO_ERROR)
			{
				wprintf(L"[rule %ws] (%ws) failed with error 0x%x\n",
					ruleInfo.ruleName.get(),
					localUserOwner.c_str(),
					ruleInfo.errorRetrievingOwnerUsername);
			}
			else
			{
				wprintf(L"[rule %ws] (%ws) successfully resolved to %ws\n",
					ruleInfo.ruleName.get(),
					localUserOwner.c_str(),
					ruleInfo.ruleOwnerUsername.c_str());
			}
            */
		}

		returnValues.emplace_back(ruleValue, std::move(ruleInfo));
	}
	return returnValues;
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

inline bool RulesMatchExactly(const NormalizedRuleInfo& lhs, const NormalizedRuleInfo& rhs) noexcept
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

	++RuleDetailsDeepMatchComparisonCount;
	const auto ruleDetailsMatch = CompareStringOrdinal(
		lhs.normalizedRuleDetails.c_str(),
		static_cast<int>(lhs.normalizedRuleDetails.size()),
		rhs.normalizedRuleDetails.c_str(),
		static_cast<int>(rhs.normalizedRuleDetails.size()),
		bIgnoreCase);
	return ruleDetailsMatch == CSTR_EQUAL;
}

inline bool RuleDetailsMatch(const NormalizedRuleInfo& lhs, const NormalizedRuleInfo& rhs)
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

	++RuleDetailsDeepMatchComparisonCount;
	const auto ruleDetailsMatch = CompareStringOrdinal(
		lhs.normalizedRuleDetails.c_str(),
		static_cast<int>(lhs.normalizedRuleDetails.size()),
		rhs.normalizedRuleDetails.c_str(),
		static_cast<int>(rhs.normalizedRuleDetails.size()),
		bIgnoreCase);
	return ruleDetailsMatch == CSTR_EQUAL;
}

inline bool SortExactMatches(const NormalizedRuleInfo& lhs, const NormalizedRuleInfo& rhs) noexcept
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

inline bool SortOnlyMatchingDetails(const NormalizedRuleInfo& lhs, const NormalizedRuleInfo& rhs) noexcept
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

inline NormalizedRuleInfo BuildFirewallRuleInfo(const wil::com_ptr<INetFwRule3>& rule) noexcept
{
	NormalizedRuleInfo ruleInfo{};
	// save for later if we determine to delete the rule (if it's a duplicate)
	// also avoids the cost of deleting each rule object as we enumerate all rules
	// (deleting the rule object requires a COM call back to the firewall service)
	ruleInfo.rule = rule;

	try
	{
		// name and description are volatile - they don't impact the final filter
		THROW_IF_FAILED(rule->get_Name(&ruleInfo.ruleName));
		THROW_IF_FAILED(rule->get_Description(&ruleInfo.ruleDescription));

		wil::unique_bstr applicationName{};
		THROW_IF_FAILED(rule->get_ApplicationName(&applicationName));
		ruleInfo.AppendValue(applicationName.get());

		wil::unique_bstr serviceName{};
		THROW_IF_FAILED(rule->get_ServiceName(&serviceName));
		ruleInfo.AppendValue(serviceName.get());

		LONG protocol{};
		THROW_IF_FAILED(rule->get_Protocol(&protocol));
		ruleInfo.AppendValue(protocol);

		wil::unique_bstr localPorts{};
		THROW_IF_FAILED(rule->get_LocalPorts(&localPorts));
		ruleInfo.AppendValue(localPorts.get());

		wil::unique_bstr remotePorts{};
		THROW_IF_FAILED(rule->get_RemotePorts(&remotePorts));
		ruleInfo.AppendValue(remotePorts.get());

		wil::unique_bstr localAddresses{};
		THROW_IF_FAILED(rule->get_LocalAddresses(&localAddresses));
		ruleInfo.AppendValue(localAddresses.get());

		wil::unique_bstr remoteAddresses{};
		THROW_IF_FAILED(rule->get_RemoteAddresses(&remoteAddresses));
		ruleInfo.AppendValue(remoteAddresses.get());

		wil::unique_bstr icmpTypesAndCodes{};
		THROW_IF_FAILED(rule->get_IcmpTypesAndCodes(&icmpTypesAndCodes));
		ruleInfo.AppendValue(icmpTypesAndCodes.get());

		NET_FW_RULE_DIRECTION direction{};
		THROW_IF_FAILED(rule->get_Direction(&direction));
		ruleInfo.AppendValue(direction);
		ruleInfo.ruleDirection = direction;

		wil::unique_variant interfaces;
		THROW_IF_FAILED(rule->get_Interfaces(&interfaces));
		ruleInfo.AppendValue(interfaces);

		wil::unique_bstr interfaceTypes;
		THROW_IF_FAILED(rule->get_InterfaceTypes(&interfaceTypes));
		ruleInfo.AppendValue(interfaceTypes.get());

		VARIANT_BOOL enabled{};
		THROW_IF_FAILED(rule->get_Enabled(&enabled));
		// not going to require matching enabled vs disabled when matching the rules
		// ruleInfo.AppendValue(enabled);
		ruleInfo.ruleEnabled = !!enabled;

		// if there are 2 rules with the same names, but different groups
		// then we want to keep them both - since presumably that have different sources
		// and thus should not be considered duplicates
		wil::unique_bstr grouping{};
		THROW_IF_FAILED(rule->get_Grouping(&grouping));
		ruleInfo.AppendValue(grouping.get());

		long profiles{};
		THROW_IF_FAILED(rule->get_Profiles(&profiles));
		ruleInfo.AppendValue(profiles);

		VARIANT_BOOL edgeTraversal{};
		THROW_IF_FAILED(rule->get_EdgeTraversal(&edgeTraversal));
		ruleInfo.AppendValue(edgeTraversal);

		NET_FW_ACTION action{};
		THROW_IF_FAILED(rule->get_Action(&action));
		ruleInfo.AppendValue(action);

		long edgeTraversalOptions{};
		THROW_IF_FAILED(rule->get_EdgeTraversalOptions(&edgeTraversalOptions));
		ruleInfo.AppendValue(edgeTraversalOptions);

		wil::unique_bstr localAppPackageId{};
		THROW_IF_FAILED(rule->get_LocalAppPackageId(&localAppPackageId));
		ruleInfo.AppendValue(localAppPackageId.get());

		wil::unique_bstr localUserOwner{};
		THROW_IF_FAILED(rule->get_LocalUserOwner(&localUserOwner));
		ruleInfo.AppendValue(localUserOwner.get());

		if (localUserOwner)
		{
			const auto userConversion = ConvertSidStringToUserName(localUserOwner.get());
			ruleInfo.errorRetrievingOwnerUsername = std::get<0>(userConversion);
			ruleInfo.ruleOwnerUsername = std::get<1>(userConversion);
			/*
			if (ruleInfo.errorRetrievingOwnerUsername != NO_ERROR)
			{
				wprintf(L"[rule %ws] (%ws) failed with error 0x%x\n",
					ruleInfo.ruleName.get(),
					localUserOwner.get(),
					ruleInfo.errorRetrievingOwnerUsername);
			}
			else
			{
				wprintf(L"[rule %ws] (%ws) successfully resolved to %ws\n",
					ruleInfo.ruleName.get(),
					localUserOwner.get(),
					ruleInfo.ruleOwnerUsername.c_str());
			}
            */
		}

		wil::unique_bstr localUserAuthorizedList{};
		THROW_IF_FAILED(rule->get_LocalUserAuthorizedList(&localUserAuthorizedList));
		ruleInfo.AppendValue(localUserAuthorizedList.get());

		wil::unique_bstr remoteUserAuthorizedList{};
		THROW_IF_FAILED(rule->get_RemoteUserAuthorizedList(&remoteUserAuthorizedList));
		ruleInfo.AppendValue(remoteUserAuthorizedList.get());

		wil::unique_bstr remoteMachineAuthorizedList{};
		THROW_IF_FAILED(rule->get_RemoteMachineAuthorizedList(&remoteMachineAuthorizedList));
		ruleInfo.AppendValue(remoteMachineAuthorizedList.get());

		long secureFlags{};
		THROW_IF_FAILED(rule->get_SecureFlags(&secureFlags));
		ruleInfo.AppendValue(secureFlags);
	}
	catch (...)
	{
		wprintf(L"Failed to read rule %ws (%ws) - 0x%x\n",
			ruleInfo.ruleName ? ruleInfo.ruleName.get() : L"(unknown)",
			ruleInfo.ruleDescription ? ruleInfo.ruleDescription.get() : L"(unknown)",
			wil::ResultFromCaughtException());
		return {};
	}

	return ruleInfo;
}
