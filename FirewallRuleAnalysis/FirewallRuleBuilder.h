#pragma once
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

inline bool RuleNamesMatch(const wil::unique_bstr& lhs, const wil::unique_bstr& rhs) noexcept
{
	constexpr BOOL bIgnoreCase = TRUE;

	// checking the string length of a BSTR is very cheap - it just reads the length field in the bstr
	// (the 32 bits allocated right before the start of the string)
	const auto lhs_length = SysStringLen(lhs.get());
	const auto rhs_length = SysStringLen(rhs.get());
	if (lhs_length != rhs_length)
	{
		return false;
	}

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
			ruleInfo.errorRetrievingOwnerUsername = NO_ERROR;

			wil::unique_any_psid convertedSid;
			if (ConvertStringSidToSidW(localUserOwner.get(), &convertedSid))
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
					ruleInfo.errorRetrievingOwnerUsername = GetLastError();
				}
				else
				{
					ruleInfo.ruleOwnerUsername.resize(nameLength);

					std::wstring referencedDomainNameString;
					if (referencedDomainNameLength > 0)
					{
						referencedDomainNameString.resize(referencedDomainNameLength);
					}
					if (!LookupAccountSidW(
						nullptr, // lookup on the local system
						convertedSid.get(),
						ruleInfo.ruleOwnerUsername.data(),
						&nameLength,
						referencedDomainNameLength > 0 ? referencedDomainNameString.data() : nullptr,
						&referencedDomainNameLength,
						&sidNameUse))
					{
						ruleInfo.errorRetrievingOwnerUsername = GetLastError();
					}
					else
					{
						// remove the embedded null-terminators from the std::wstring objects
						ruleInfo.ruleOwnerUsername.resize(ruleInfo.ruleOwnerUsername.size() - 1);
						if (referencedDomainNameLength > 0)
						{
							referencedDomainNameString.resize(referencedDomainNameString.size() - 1);
						}

						if (!referencedDomainNameString.empty())
						{
							std::wstring fullOwnerName{ std::move(referencedDomainNameString) };
							fullOwnerName.append(L"\\");
							fullOwnerName.append(ruleInfo.ruleOwnerUsername);
							ruleInfo.ruleOwnerUsername = std::move(fullOwnerName);
						}
					}
				}
			}
			else
			{
				ruleInfo.errorRetrievingOwnerUsername = GetLastError();
			}

			if (ruleInfo.errorRetrievingOwnerUsername != NO_ERROR)
			{
				wprintf(L"[rule %ws] %ws(%ws) failed with error 0x%x\n",
					ruleInfo.ruleName.get(),
					convertedSid.is_valid() ? L"LookupAccountSid" : L"ConvertStringSidToSidW",
					localUserOwner.get(),
					ruleInfo.errorRetrievingOwnerUsername);
			}
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
