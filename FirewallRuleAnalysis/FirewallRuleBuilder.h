#pragma once
#include <string>

#include <Windows.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/resource.h>

struct NormalizedRuleInfo
{
	wil::unique_bstr ruleName;
	wil::unique_bstr ruleDescription;
	std::wstring normalizedRuleDetails;
	NET_FW_RULE_DIRECTION ruleDirection;
	bool ruleEnabled;

	// guarantee this object is never copied, only moved
	NormalizedRuleInfo(const NormalizedRuleInfo&) = delete;
	NormalizedRuleInfo& operator=(const NormalizedRuleInfo&) = delete;

	NormalizedRuleInfo(NormalizedRuleInfo&&) = default;
	NormalizedRuleInfo& operator=(NormalizedRuleInfo&&) = default;

	NormalizedRuleInfo() = default;
	~NormalizedRuleInfo() = default;

	void AppendValue(const wil::unique_bstr& value)
	{
		if (value && value.get()[0] != L'\0')
		{
			normalizedRuleDetails.append(value.get());
		}
	}

	// the one VARIANT that's returned from the Firewall Rule interface
	// is for an array of strings for Interfaces
	void AppendValue(const wil::unique_variant& value)
	{
		if (value.vt == VT_EMPTY)
		{
			// it's acceptable to be either EMPTY
			// or an ARRAY of VARIANTs
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
					normalizedRuleDetails.append(element.bstrVal);
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

inline bool RulesMatchExactly(const NormalizedRuleInfo& lhs, const NormalizedRuleInfo& rhs)
{
	constexpr BOOL bIgnoreCase = TRUE;

	if (lhs.normalizedRuleDetails.size() != rhs.normalizedRuleDetails.size())
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

	const auto ruleDetailsMatch = CompareStringOrdinal(
		lhs.normalizedRuleDetails.c_str(),
		static_cast<int>(lhs.normalizedRuleDetails.size()),
		rhs.normalizedRuleDetails.c_str(),
		static_cast<int>(rhs.normalizedRuleDetails.size()),
		bIgnoreCase);
	if (ruleDetailsMatch != CSTR_EQUAL)
	{
		return false;
	}

	return true;
}

inline bool RuleDetailsMatch(const NormalizedRuleInfo& lhs, const NormalizedRuleInfo& rhs)
{
	constexpr BOOL bIgnoreCase = TRUE;

	if (lhs.normalizedRuleDetails.size() != rhs.normalizedRuleDetails.size())
	{
		return false;
	}

	const auto ruleDetailsMatch = CompareStringOrdinal(
		lhs.normalizedRuleDetails.c_str(),
		static_cast<int>(lhs.normalizedRuleDetails.size()),
		rhs.normalizedRuleDetails.c_str(),
		static_cast<int>(rhs.normalizedRuleDetails.size()),
		bIgnoreCase);
	if (ruleDetailsMatch != CSTR_EQUAL)
	{
		return false;
	}

	return true;
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

	return CSTR_LESS_THAN == CompareStringOrdinal(
		lhs.normalizedRuleDetails.c_str(),
		static_cast<int>(lhs.normalizedRuleDetails.size()),
		rhs.normalizedRuleDetails.c_str(),
		static_cast<int>(rhs.normalizedRuleDetails.size()),
		bIgnoreCase);
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

	return CSTR_LESS_THAN == CompareStringOrdinal(
		lhs.normalizedRuleDetails.c_str(),
		static_cast<int>(lhs.normalizedRuleDetails.size()),
		rhs.normalizedRuleDetails.c_str(),
		static_cast<int>(rhs.normalizedRuleDetails.size()),
		bIgnoreCase);
}

inline NormalizedRuleInfo BuildFirewallRuleInfo(const wil::com_ptr<INetFwRule>& rule)
{
	NormalizedRuleInfo ruleInfo{};

	// QI to the latest firewall rule interface
	wil::com_ptr<INetFwRule3> latestRule;
	rule.query_to<INetFwRule3>(&latestRule);

	// name and description are volatile - they don't impact the final filter
	THROW_IF_FAILED(latestRule->get_Name(&ruleInfo.ruleName));
	THROW_IF_FAILED(latestRule->get_Description(&ruleInfo.ruleDescription));

	try
	{
		wil::unique_bstr applicationName{};
		THROW_IF_FAILED(latestRule->get_ApplicationName(&applicationName));
		ruleInfo.AppendValue(applicationName);

		wil::unique_bstr serviceName{};
		THROW_IF_FAILED(latestRule->get_ServiceName(&serviceName));
		ruleInfo.AppendValue(serviceName);

		LONG protocol{};
		THROW_IF_FAILED(latestRule->get_Protocol(&protocol));
		ruleInfo.AppendValue(protocol);

		wil::unique_bstr localPorts{};
		THROW_IF_FAILED(latestRule->get_LocalPorts(&localPorts));
		ruleInfo.AppendValue(localPorts);

		wil::unique_bstr remotePorts{};
		THROW_IF_FAILED(latestRule->get_RemotePorts(&remotePorts));
		ruleInfo.AppendValue(remotePorts);

		wil::unique_bstr localAddresses{};
		THROW_IF_FAILED(latestRule->get_LocalAddresses(&localAddresses));
		ruleInfo.AppendValue(localAddresses);

		wil::unique_bstr remoteAddresses{};
		THROW_IF_FAILED(latestRule->get_RemoteAddresses(&remoteAddresses));
		ruleInfo.AppendValue(remoteAddresses);

		wil::unique_bstr icmpTypesAndCodes{};
		THROW_IF_FAILED(latestRule->get_IcmpTypesAndCodes(&icmpTypesAndCodes));
		ruleInfo.AppendValue(icmpTypesAndCodes);

		NET_FW_RULE_DIRECTION direction{};
		THROW_IF_FAILED(latestRule->get_Direction(&direction));
		ruleInfo.AppendValue(direction);
		ruleInfo.ruleDirection = direction;

		wil::unique_variant interfaces;
		THROW_IF_FAILED(latestRule->get_Interfaces(&interfaces));
		ruleInfo.AppendValue(interfaces);

		wil::unique_bstr interfaceTypes;
		THROW_IF_FAILED(latestRule->get_InterfaceTypes(&interfaceTypes));
		ruleInfo.AppendValue(interfaceTypes);

		VARIANT_BOOL enabled{};
		THROW_IF_FAILED(latestRule->get_Enabled(&enabled));
		// not going to require matching enabled vs disabled when matching the rules
		// ruleInfo.AppendValue(enabled);
		ruleInfo.ruleEnabled = !!enabled;

		wil::unique_bstr grouping{};
		THROW_IF_FAILED(latestRule->get_Grouping(&grouping));
		ruleInfo.AppendValue(grouping);

		long profiles{};
		THROW_IF_FAILED(latestRule->get_Profiles(&profiles));
		ruleInfo.AppendValue(profiles);

		VARIANT_BOOL edgeTraversal{};
		THROW_IF_FAILED(latestRule->get_EdgeTraversal(&edgeTraversal));
		ruleInfo.AppendValue(edgeTraversal);

		NET_FW_ACTION action{};
		THROW_IF_FAILED(latestRule->get_Action(&action));
		ruleInfo.AppendValue(action);

		long edgeTraversalOptions{};
		THROW_IF_FAILED(latestRule->get_EdgeTraversalOptions(&edgeTraversalOptions));
		ruleInfo.AppendValue(edgeTraversalOptions);

		wil::unique_bstr localAppPackageId{};
		THROW_IF_FAILED(latestRule->get_LocalAppPackageId(&localAppPackageId));
		ruleInfo.AppendValue(localAppPackageId);

		wil::unique_bstr localUserOwner{};
		THROW_IF_FAILED(latestRule->get_LocalUserOwner(&localUserOwner));
		ruleInfo.AppendValue(localUserOwner);

		wil::unique_bstr localUserAuthorizedList{};
		THROW_IF_FAILED(latestRule->get_LocalUserAuthorizedList(&localUserAuthorizedList));
		ruleInfo.AppendValue(localUserAuthorizedList);

		wil::unique_bstr remoteUserAuthorizedList{};
		THROW_IF_FAILED(latestRule->get_RemoteUserAuthorizedList(&remoteUserAuthorizedList));
		ruleInfo.AppendValue(remoteUserAuthorizedList);

		wil::unique_bstr remoteMachineAuthorizedList{};
		THROW_IF_FAILED(latestRule->get_RemoteMachineAuthorizedList(&remoteMachineAuthorizedList));
		ruleInfo.AppendValue(remoteMachineAuthorizedList);

		long secureFlags{};
		THROW_IF_FAILED(latestRule->get_SecureFlags(&secureFlags));
		ruleInfo.AppendValue(secureFlags);
	}
	catch (...)
	{
		wprintf(L"Failed to read rule %ws (%ws) - 0x%x\n",
			ruleInfo.ruleName.get(), ruleInfo.ruleDescription.get(), wil::ResultFromCaughtException());
		throw;
	}

	return ruleInfo;
}
