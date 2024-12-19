#pragma once
#include <optional>
#include <regex>
#include <string>
#include <cwctype>

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
	NormalizedRuleInfo(const NormalizedRuleInfo&) = delete;
	NormalizedRuleInfo& operator=(const NormalizedRuleInfo&) = delete;

	NormalizedRuleInfo(NormalizedRuleInfo&&) noexcept = default;
	NormalizedRuleInfo& operator=(NormalizedRuleInfo&&) noexcept = default;

	NormalizedRuleInfo() = default;
	~NormalizedRuleInfo() = default;

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
	AppIsolation
};
constexpr auto* LocalFirewallRulePath = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
constexpr auto* AppIsoFirewallRulePath = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules";

struct RegistryToComMapping
{
	const std::vector<const wchar_t*> registryKeywords;
	const wchar_t* matchingComMethod = nullptr;
	const uint32_t maxOccurrences = 0;
	const std::function<void(const std::wstring&, NormalizedRuleInfo&)> valueToRuleInfoFn = nullptr;
	uint32_t numOccurrences{ 0 };
};

// returns the [registry value name],[parsed rule name]
inline std::vector<std::tuple<std::wstring, NormalizedRuleInfo>> ReadRegistryRules(FirewallRuleStore store)
{
	std::vector<std::tuple<std::wstring, NormalizedRuleInfo>> returnValues;
	wil::unique_hkey localRuleKey;
	switch (store)
	{
	case FirewallRuleStore::Local:
	{
		localRuleKey = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, LocalFirewallRulePath);
		break;
	}
	case FirewallRuleStore::AppIsolation:
	{
		localRuleKey = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, AppIsoFirewallRulePath);
		break;
	}
	}
	for (const auto& value_data : wil::make_range(wil::reg::value_iterator{ localRuleKey.get() }, wil::reg::value_iterator{}))
	{
		if (value_data.type != REG_SZ)
		{
			wprintf(L"***** Broken registry value -- type is not REG_SZ : %d *****\n", value_data.type);
			DebugBreak();
			return {};
		}

		// ruleValue cannot be const since we will eventually need modify-able iterators into this string
		auto ruleValue = wil::reg::get_value_string(localRuleKey.get(), value_data.name.c_str());

		NormalizedRuleInfo ruleInfo{};

		// ReSharper disable StringLiteralTypo
		RegistryToComMapping registryToComMapping[]
		{
			{{L"name"}, L"get_Name", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.ruleName = wil::make_bstr(value.c_str());
			}},
			{{L"desc"}, L"get_Description", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.ruleDescription = wil::make_bstr(value.c_str());
			}},
			{{L"embedctxt"}, L"get_Grouping", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.ruleGrouping = wil::make_bstr(value.c_str());
				ruleInfo.AppendValue(ruleInfo.ruleGrouping.get());
			}},
			{{L"active"}, L"get_Enabled", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
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
					wprintf(L"***** Broken registry value -- active should be TRUE or FALSE : %ws *****\n", value.c_str());
					DebugBreak();
				}
			}},
			{{L"action"}, L"get_Action", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
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
					wprintf(L"***** Broken registry value -- action should be ALLOW or BLOCK : %ws *****\n", value.c_str());
					DebugBreak();
				}
			}},
			{{L"dir"}, L"get_Direction", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
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
					wprintf(L"***** Broken registry value -- action should be ALLOW or BLOCK : %ws *****\n", value.c_str());
					DebugBreak();
				}
			}},
			{{L"protocol"}, L"get_Protocol", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				// get_Protocol returns a LONG
				// throws if not a valid long number
				ruleInfo.AppendValue(std::stol(value));
			}},
			{{L"profile"}, L"get_Profiles", 3, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				// get_Profiles returns a LONG that is the OR combination of NET_FW_PROFILE_TYPE2 enums
				// must be =Private, =Public, =Domain
				bool valid = false;
				if (value.size() == 6 && (0 == wmemcmp(value.c_str(), L"public", 6)))
				{
					valid = true;
				    ruleInfo.ruleProfiles |= NET_FW_PROFILE_TYPE2::NET_FW_PROFILE2_PUBLIC;
				}
				else if (value.size() == 7 && (0 == wmemcmp(value.c_str(), L"private", 7)))
                {
					valid = true;
				    ruleInfo.ruleProfiles |= NET_FW_PROFILE_TYPE2::NET_FW_PROFILE2_PRIVATE;
                }
				else if (value.size() == 6 && (0 == wmemcmp(value.c_str(), L"domain", 6)))
                {
					valid = true;
				    ruleInfo.ruleProfiles |= NET_FW_PROFILE_TYPE2::NET_FW_PROFILE2_DOMAIN;
                }
				
				if (!valid)
				{
					wprintf(L"***** Broken registry value -- profile should be PUBLIC, PRIVATE, or DOMAIN : %ws *****\n", value.c_str());
					DebugBreak();
				}
			}},
			{{L"luown"}, L"get_LocalUserOwner", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.AppendValueLowerCase(value);
			}},
			{{L"luauth", L"luauth2_24"}, L"get_LocalUserAuthorizedList", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.AppendValueLowerCase(value);
			}},
			{{L"app"}, L"get_ApplicationName", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.AppendValueLowerCase(value);
			}},
			{{L"apppkgid"}, L"get_LocalAppPackageId", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.AppendValueLowerCase(value);
			}},
			{{L"svc"}, L"get_ServiceName", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				ruleInfo.AppendValueLowerCase(value);
			}},
			{{L"edge"}, L"get_EdgeTraversal", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
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
					wprintf(L"***** Broken registry value -- edge should be TRUE or FALSE : %ws *****\n", value.c_str());
					DebugBreak();
				}
			}},
			{{L"defer"}, L"get_EdgeTraversalOptions", 1, [](const std::wstring& value, NormalizedRuleInfo& ruleInfo)
			{
				// get_EdgeTraversalOptions returns a LONG 
				// throws if not a valid long number
				ruleInfo.AppendValue(std::stol(value));
			}},
			{{L"if"}, L"get_Interfaces", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"iftype", L"iftype2_23"}, L"get_InterfaceTypes", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"la4", L"la6"}, L"get_LocalAddresses", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"ra4", L"ra42", L"ra43", L"ra6", L"ra62", L"ra63"}, L"get_RemoteAddresses", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"lport", L"lport2_10", L"lport2_20", L"lport2_24", L"lport2_29"}, L"get_LocalPorts", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"rport", L"rport2_10", L"rport2_25"}, L"get_RemotePorts", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"icmp4", L"icmp6"}, L"get_IcmpTypesAndCodes", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"ruauth"}, L"get_RemoteUserAuthorizedList", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"rmauth"}, L"get_RemoteMachineAuthorizedList", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
			{{L"security", L"security2", L"security2_9"}, L"get_SecureFlags", INFINITE, [](const std::wstring&, NormalizedRuleInfo&)
			{
				// TODO
			}},
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
				wprintf(L"***** Broken registry value -- empty Keyword string : %ws *****\n", std::wstring(startOfKeyword, endingIterator).c_str());
				DebugBreak();
				return {};
			}

			// now we know the end() of the keyword, at the '='
			auto endOfKeyword = stringIterator;
			if (endOfKeyword - startOfKeyword == 1)
			{
				wprintf(L"***** Broken registry value -- the string length of Value is zero : %ws *****\n", std::wstring(startOfKeyword, endingIterator).c_str());
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
				wprintf(L"***** Broken registry value -- invalid Keyword=Value string : %ws *****\n", std::wstring(startOfKeyword, endingIterator).c_str());
				DebugBreak();
				return {};
			}

			stringIterator = std::find(stringIterator, endingIterator, L'|');
			// now we know the end() of the next keyword
			auto endOfValue = stringIterator;
			if (endOfValue - startOfValue == 0)
			{
				wprintf(L"***** Broken registry value -- empty Value string : %ws *****\n", std::wstring(startOfKeyword, endingIterator).c_str());
				DebugBreak();
				return {};
			}

			// leave stringIterator referencing the last | character
			// since that will be the start of the key/value pair for the next loop iteration

			// now find the matching keyword
			auto compareKeywords = [](const std::wstring::iterator& registryKeywordBegin, const std::wstring::iterator& registryKeywordEnd, PCWSTR keyword) -> bool
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
					wprintf(L"***** Broken registry value -- invalid Keyword string : %ws *****\n", std::wstring(startOfKeyword, endOfKeyword).c_str());
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
							wprintf(L"***** Broken registry value -- repeated Keyword string : %ws *****\n", std::wstring(startOfKeyword, endOfKeyword).c_str());
							DebugBreak();
							return {};
						}
					}

					mapping.valueToRuleInfoFn(std::wstring(startOfValue, endOfValue), ruleInfo);
					break;
				}
			}

			if (!foundMapping)
			{
				wprintf(L"***** Broken registry value -- unknown Keyword string : %ws *****\n", std::wstring(startOfKeyword, endOfKeyword).c_str());
				DebugBreak();
				return {};
			}
		}

		returnValues.emplace_back(std::make_tuple(std::move(ruleValue), std::move(ruleInfo)));
	}

	std::ranges::sort(returnValues, [](const std::tuple<std::wstring, NormalizedRuleInfo>& lhs, const std::tuple<std::wstring, NormalizedRuleInfo>& rhs)
		{
			// just sort on the string read from the registry
			return std::get<0>(lhs) < std::get<0>(rhs);
		});
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
		ruleInfo.ruleGrouping = std::move(grouping);

		LONG profiles{};
		THROW_IF_FAILED(rule->get_Profiles(&profiles));
		ruleInfo.AppendValue(profiles);
		ruleInfo.ruleProfiles = profiles;

		VARIANT_BOOL edgeTraversal{};
		THROW_IF_FAILED(rule->get_EdgeTraversal(&edgeTraversal));
		ruleInfo.AppendValue(edgeTraversal);

		NET_FW_ACTION action{};
		THROW_IF_FAILED(rule->get_Action(&action));
		ruleInfo.AppendValue(action);
		ruleInfo.ruleAction = action;

		LONG edgeTraversalOptions{};
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

		LONG secureFlags{};
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
