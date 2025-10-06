#pragma once

#include <chrono>
#include <string>

#include <Windows.h>
#include <netfw.h>
#include <sddl.h>

#include "WfpCounters.h"

#include <wil/resource.h>

struct NormalizedFirewallRule
{
	PFW_RULE fwRule{};
	std::wstring ruleId;
	NormalizedString ruleName;
	std::wstring ruleDescription;

	NormalizedString normalizedRuleDetails;

	std::optional<bool> targetApplicationExists{ std::nullopt };

	std::wstring localUserOwnerName;
	std::wstring localUserDomainName;
	std::optional<bool> userNameResolvedSuccessfully{ std::nullopt };

	std::optional<bool> userNameResolvedSuccessfullyWithLocalProfile{ std::nullopt };

	size_t filter_count{ 0 };
	size_t filter_condition_count{ 0 };
	size_t duplicate_rule_count{ 0 };

	bool ruleEnabled = false;
	bool ruleDeleted = false;

	// guarantee this object is never copied, only moved
	NormalizedFirewallRule(const NormalizedFirewallRule&) = delete;
	NormalizedFirewallRule& operator=(const NormalizedFirewallRule&) = delete;

	NormalizedFirewallRule(NormalizedFirewallRule&&) noexcept = default;
	NormalizedFirewallRule& operator=(NormalizedFirewallRule&&) noexcept = default;

	NormalizedFirewallRule() = default;
	~NormalizedFirewallRule() = default;

	static NormalizedFirewallRule BuildFromFWRule(PFW_RULE fwRule)
	{
		NormalizedFirewallRule normalizedRule;
		normalizedRule.fwRule = fwRule;

		if (fwRule->wszName)
		{
			std::wstring ruleName(fwRule->wszName);
			ProcessForStringResource(ruleName);
			normalizedRule.ruleName = NormalizedString::Normalize(ruleName);
		}

		if (fwRule->wszDescription)
		{
			normalizedRule.ruleDescription.assign(fwRule->wszDescription);
			ProcessForStringResource(normalizedRule.ruleDescription);
		}
		if (fwRule->wszRuleId)
		{
			normalizedRule.ruleId.assign(fwRule->wszRuleId);
		}

		normalizedRule.AppendValue(fwRule->wSchemaVersion);
		normalizedRule.AppendValue(fwRule->dwProfiles);
		normalizedRule.AppendValue(fwRule->Direction);
		normalizedRule.AppendValue(fwRule->wIpProtocol);
		// unnamed union for ports and ICMP types based on the IP Protocol
		switch (fwRule->wIpProtocol)
		{
		case 6:
		case 17:
		{
			// read TCP and UDP ports
			normalizedRule.AppendValue(fwRule->LocalPorts.wPortKeywords);
			normalizedRule.AppendValue(fwRule->LocalPorts.Ports);
			normalizedRule.AppendValue(fwRule->RemotePorts.wPortKeywords);
			normalizedRule.AppendValue(fwRule->RemotePorts.Ports);
			break;
		}

		case 1:
		case 58:
		{
			// read ICMP fields
			normalizedRule.AppendValue(fwRule->V4TypeCodeList);
			normalizedRule.AppendValue(fwRule->V6TypeCodeList);
			break;
		}

		// we don't have any other protocol-specific firewall rule properties
		default:
			break;
		}

		normalizedRule.AppendValue(fwRule->LocalAddresses.dwV4AddressKeywords);
		normalizedRule.AppendValue(fwRule->LocalAddresses.dwV6AddressKeywords);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V4SubNets);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V4Ranges);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V6SubNets);
		normalizedRule.AppendValue(fwRule->LocalAddresses.V6Ranges);

		normalizedRule.AppendValue(fwRule->RemoteAddresses.dwV4AddressKeywords);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.dwV6AddressKeywords);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V4SubNets);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V4Ranges);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V6SubNets);
		normalizedRule.AppendValue(fwRule->RemoteAddresses.V6Ranges);

		normalizedRule.AppendValue(fwRule->LocalInterfaceIds);
		normalizedRule.AppendValue(fwRule->dwLocalInterfaceTypes);
		normalizedRule.AppendValue(fwRule->wszLocalApplication);
		normalizedRule.CheckIfFileExists();
		normalizedRule.AppendValue(fwRule->wszLocalService);

		normalizedRule.AppendValue(fwRule->Action);
		normalizedRule.AppendValue(fwRule->wFlags);
		normalizedRule.ruleEnabled = (fwRule->wFlags & FW_RULE_FLAGS_ACTIVE) == FW_RULE_FLAGS_ACTIVE;

		normalizedRule.AppendValue(fwRule->wszRemoteMachineAuthorizationList);
		normalizedRule.AppendValue(fwRule->wszRemoteUserAuthorizationList);
		normalizedRule.AppendValue(fwRule->wszEmbeddedContext);
		normalizedRule.AppendValue(fwRule->PlatformValidityList);

		normalizedRule.AppendValue(fwRule->Status);
		normalizedRule.AppendValue(fwRule->Origin);
		normalizedRule.AppendValue(fwRule->wszGPOName);
		normalizedRule.AppendValue(fwRule->Reserved);

		normalizedRule.AppendValue(fwRule->pMetaData);

		normalizedRule.AppendValue(fwRule->wszLocalUserAuthorizationList);
		normalizedRule.AppendValue(fwRule->wszPackageId);
		normalizedRule.AppendValue(fwRule->wszLocalUserOwner);
		normalizedRule.ProcessLocalUserSid();

		normalizedRule.AppendValue(fwRule->dwTrustTupleKeywords);
		normalizedRule.AppendValue(fwRule->OnNetworkNames);
		normalizedRule.AppendValue(fwRule->wszSecurityRealmId);
		normalizedRule.AppendValue(fwRule->wFlags2);
		normalizedRule.AppendValue(fwRule->RemoteOutServerNames);
		normalizedRule.AppendValue(fwRule->wszFqbn);
		normalizedRule.AppendValue(fwRule->compartmentId);
		normalizedRule.AppendValue(fwRule->providerContextKey);

		normalizedRule.AppendValue(fwRule->RemoteDynamicKeywordAddresses);
		normalizedRule.AppendValue(fwRule->wszPackageFamilyName);
		return normalizedRule;
	}

private:

	static void ProcessForStringResource(std::wstring& string_value)
	{
		if (!string_value.starts_with(L"@"))
		{
			return;
		}

		if (IsRuleAnAppxRule(string_value))
		{
			return;
		}

		const auto comma = string_value.find(L',');
		if (comma == std::wstring::npos)
		{
			return;
		}

		const auto file_name = string_value.substr(1, comma - 1);
		auto string_index = string_value.substr(comma + 1);

		const auto expanded_file_name = ExpandString(file_name);
		if (expanded_file_name.empty())
		{
			if (DebugPrintEnabled())
			{
				std::printf("Failed to expand the file name '%ls'\n", file_name.c_str());
			}
			return;
		}

		const wil::unique_hmodule file_name_hmod{ LoadLibraryExW(expanded_file_name.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE) };
		if (!file_name_hmod)
		{
			const auto gle = GetLastError();
			if (DebugPrintEnabled())
			{
				std::printf("Failed to LoadLibraryExW(%ls) (0x%lx)\n", expanded_file_name.c_str(), gle);
			}
			return;
		}

		uint32_t converted_value = 0;
		const auto conversion_error = wil::ResultFromException([&] {
			// strip the leading '-' from the string index if it exists
			if (string_index.starts_with(L'-'))
			{
				string_index = string_index.substr(1, string_index.size() - 1);
			}
			converted_value = std::stoul(string_index);
			});
		if (FAILED(conversion_error))
		{
			if (DebugPrintEnabled())
			{
				std::printf("Failed to convert string index '%ls' to a number: 0x%lx\n", string_index.c_str(), conversion_error);  // NOLINT(clang-diagnostic-format)
			}
			return;
		}

		// try to load the string resource
		PCWSTR raw_pointer_to_resource{ nullptr };
		const auto conversion_size = LoadStringW(
			file_name_hmod.get(),
			converted_value,
			reinterpret_cast<LPWSTR>(&raw_pointer_to_resource),
			0);
		if (conversion_size == 0)
		{
			const auto gle = GetLastError();
			if (DebugPrintEnabled())
			{
				std::printf("Failed to LoadStringW(%ls, %u) (0x%lx)\n", expanded_file_name.c_str(), converted_value, gle);
			}
			return;
		}

		std::wstring string_resource{ raw_pointer_to_resource, raw_pointer_to_resource + conversion_size };
		string_value.swap(string_resource);
	}

	static bool IsRuleAnAppxRule(const std::wstring& rule_name)
	{
		// 16 == length of '@{' (2) + length of 'ms-resource://' (14)
		constexpr size_t minRuleNameLength = 16;
		if (rule_name.length() < minRuleNameLength)
		{
			return false;
		}
		if (rule_name[0] != L'@' || rule_name[1] != '{')
		{
			return false;
		}

		// now search for ms-resource://  --- this is case-sensitive, but that seems correct for APPX rules
		constexpr auto* appxResourceStringId = L"ms-resource://";
		return rule_name.find(appxResourceStringId) != std::wstring::npos;
	}

	static std::wstring ExpandString(const std::wstring& original_filename)
	{
		// resolve any environment variables in the string, then verify it exists
		std::wstring expanded_string;
		expanded_string.resize(original_filename.size() + 10, L' ');

		for (;;)
		{
			const auto expanded_size = ExpandEnvironmentStringsW(original_filename.c_str(), expanded_string.data(), static_cast<DWORD>(expanded_string.size()));
			if (expanded_size == 0)
			{
				const auto gle = GetLastError();
				if (DebugPrintEnabled())
				{
					std::printf("Failed to ExpandEnvironmentStrings(%ls) (0x%lx)", original_filename.c_str(), gle);
				}
				return {};
			}

			if (expanded_size <= expanded_string.size())
			{
				// the string was expanded, and it fits in the buffer
				expanded_string.resize(expanded_size - 1); // trim the null terminator
				break;
			}

			expanded_string.resize(expanded_size, L' '); // the buffer was not big enough, resize it and try again
		}

		return expanded_string;
	}

	void ProcessLocalUserSid()
	{
		if (fwRule->wszLocalUserOwner)
		{
			// process the local user owner string for string resources
			wil::unique_sid localUserOwnerSid;
			if (!ConvertStringSidToSid(fwRule->wszLocalUserOwner, localUserOwnerSid.addressof()))
			{
				const auto gle = GetLastError();
				if (DebugPrintEnabled())
				{
					std::printf("Failed to ConvertStringSidToSid(%ls) (0x%lx)\n", fwRule->wszLocalUserOwner, gle);
				}
				userNameResolvedSuccessfully = false;
				return;
			}

			DWORD localUserOwnerNameSize = 0;
			DWORD cchReferencedDomainName = 0;
			SID_NAME_USE sid_name_use{};
			if (!LookupAccountSidW(nullptr, localUserOwnerSid.get(), localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
			{
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					localUserOwnerName.resize(localUserOwnerNameSize);
					localUserDomainName.resize(cchReferencedDomainName);

					if (!LookupAccountSidW(nullptr, localUserOwnerSid.get(), localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
					{
						const auto gle = GetLastError();
						if (DebugPrintEnabled())
						{
							std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", fwRule->wszLocalUserOwner, gle);
						}
						userNameResolvedSuccessfully = false;
						return;
					}

					userNameResolvedSuccessfully = true;

					if (DebugPrintEnabled())
					{
						if (localUserDomainName.empty())
						{
							std::printf("Successfully converted LocalUserOwner SID %ls to %ls\n", fwRule->wszLocalUserOwner, localUserOwnerName.c_str());
						}
						else
						{
							std::printf("Successfully converted LocalUserOwner SID %ls to %ls\\%ls\n", fwRule->wszLocalUserOwner, localUserDomainName.c_str(), localUserOwnerName.c_str());
						}
					}
				}
				else
				{
					const auto gle = GetLastError();
					if (DebugPrintEnabled())
					{
						std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", fwRule->wszLocalUserOwner, gle);
					}
					userNameResolvedSuccessfully = false;
				}
			}
			else
			{
				// should never happen
				FAIL_FAST();
			}
		}
	}

	void CheckIfFileExists()
	{
		if (!fwRule->wszLocalApplication)
		{
			return;
		}

		const std::wstring original_filename{ fwRule->wszLocalApplication };
		if (IsRuleAnAppxRule(fwRule->wszLocalApplication))
		{
			// appx rules must be checked using appx APIs to check for that package
			return;
		}

		if (CompareStringOrdinal(fwRule->wszLocalApplication, -1, L"SYSTEM", -1, TRUE) == CSTR_EQUAL)
		{
			// this refers to a kernel component
			return;
		}

		const auto expanded_string = ExpandString(original_filename);
		if (expanded_string.empty())
		{
			// failed to expand the string, cannot check if it exists
			return;
		}

		// now check if the file exists
		WIN32_FIND_DATA find_data{};
		HANDLE found_file = FindFirstFileExW(
			expanded_string.c_str(),
			FindExInfoBasic,
			&find_data,
			FindExSearchNameMatch,
			nullptr,
			0);
		if (found_file == INVALID_HANDLE_VALUE)
		{
			const auto gle = GetLastError();
			if (DebugPrintEnabled())
			{
				std::printf("Failed to FindFirstFileExW(%ls) (0x%lx)\n", expanded_string.c_str(), gle);
			}
			targetApplicationExists = false;
		}
		else
		{
			targetApplicationExists = true;
			FindClose(found_file);
		}
	}

	void AppendValue(const GUID& guid)
	{
		AppendValue(guid.Data1);
		AppendValue(guid.Data2);
		AppendValue(guid.Data3);
		// append as 1 64-bit integer
		static_assert(sizeof(guid.Data4) == sizeof(uint64_t));
		const unsigned char* data4 = guid.Data4;
		const uint64_t* data4_as_uint64 = reinterpret_cast<const uint64_t*>(data4);
		AppendValue(*data4_as_uint64);
	}

	void AppendValue(const FW_PORT_RANGE_LIST& list)
	{
		const auto* ports = list.pPorts;
		const auto ports_count = list.dwNumEntries;
		if (ports_count == 0 || !ports)
		{
			if (ports_count != 0 || ports)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& port : wil::make_range(ports, ports + ports_count))
			{
				AppendValue(port.wBegin);
				AppendValue(port.wEnd);
			}
		}
	}

	void AppendValue(const FW_ICMP_TYPE_CODE_LIST& list)
	{
		const auto* icmp_list = list.pEntries;
		const auto icmp_count = list.dwNumEntries;
		if (icmp_count == 0 || !icmp_list)
		{
			if (icmp_count != 0 || icmp_list)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& icmp : wil::make_range(icmp_list, icmp_list + icmp_count))
			{
				AppendValue(icmp.bType);
				AppendValue(icmp.wCode);
			}
		}
	}

	void AppendValue(const FW_IPV4_SUBNET_LIST& list)
	{
		const auto* subnets = list.pSubNets;
		const auto subnet_count = list.dwNumEntries;
		if (subnet_count == 0 || !subnets)
		{
			if (subnet_count != 0 || subnets)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& subnet : wil::make_range(subnets, subnets + subnet_count))
			{
				AppendValue(subnet.dwAddress);
				AppendValue(subnet.dwSubNetMask);
			}
		}
	}

	void AppendValue(const FW_IPV6_SUBNET_LIST& list)
	{
		const auto* subnets = list.pSubNets;
		const auto subnet_count = list.dwNumEntries;
		if (subnet_count == 0 || !subnets)
		{
			if (subnet_count != 0 || subnets)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& subnet : wil::make_range(subnets, subnets + subnet_count))
			{
				// append as 2 64-bit integers
				static_assert(sizeof(subnet.Address) == (2 * sizeof(uint64_t)));
				const BYTE* address_buffer = subnet.Address;
				const uint64_t* first_integer = reinterpret_cast<const uint64_t*>(address_buffer);
				AppendValue(*first_integer);
				const uint64_t* second_integer = reinterpret_cast<const uint64_t*>(address_buffer + sizeof(first_integer));
				AppendValue(*second_integer);
			}
		}
	}

	void AppendValue(const FW_IPV4_RANGE_LIST& list)
	{
		const auto* ranges = list.pRanges;
		const auto range_count = list.dwNumEntries;
		if (range_count == 0 || !ranges)
		{
			if (range_count != 0 || ranges)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& range : wil::make_range(ranges, ranges + range_count))
			{
				AppendValue(range.dwBegin);
				AppendValue(range.dwEnd);
			}
		}
	}

	void AppendValue(const FW_IPV6_RANGE_LIST& list)
	{
		const auto* ranges = list.pRanges;
		const auto range_count = list.dwNumEntries;
		if (range_count == 0 || !ranges)
		{
			if (range_count != 0 || ranges)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& range : wil::make_range(ranges, ranges + range_count))
			{
				// append as 2 64-bit integers
				static_assert(sizeof(range.Begin) == (2 * sizeof(uint64_t)));
				const BYTE* begin_buffer = range.Begin;
				const uint64_t* first_begin_integer = reinterpret_cast<const uint64_t*>(begin_buffer);
				AppendValue(*first_begin_integer);
				const uint64_t* second_begin_integer = reinterpret_cast<const uint64_t*>(begin_buffer + sizeof(first_begin_integer));
				AppendValue(*second_begin_integer);
				// append as 2 64-bit integers
				static_assert(sizeof(range.End) == (2 * sizeof(uint64_t)));
				const BYTE* end_buffer = range.End;
				const uint64_t* first_end_integer = reinterpret_cast<const uint64_t*>(end_buffer);
				AppendValue(*first_end_integer);
				const uint64_t* second_end_integer = reinterpret_cast<const uint64_t*>(end_buffer + sizeof(first_end_integer));
				AppendValue(*second_end_integer);
			}
		}
	}

	void AppendValue(const FW_INTERFACE_LUIDS& interface_luids)
	{
		const auto* luids = interface_luids.pLUIDs;
		const auto luids_count = interface_luids.dwNumLUIDs;
		if (luids_count == 0 || !luids)
		{
			if (luids_count != 0 || luids)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& luid : wil::make_range(luids, luids + luids_count))
			{
				AppendValue(luid);
			}
		}
	}

	void AppendValue(const FW_OS_PLATFORM_LIST& list)
	{
		const auto* platforms = list.pPlatforms;
		const auto platform_count = list.dwNumEntries;
		if (platform_count == 0 || !platforms)
		{
			if (platform_count != 0 || platforms)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& platform : wil::make_range(platforms, platforms + platform_count))
			{
				AppendValue(platform.bPlatform);
				AppendValue(platform.bMajorVersion);
				AppendValue(platform.bMinorVersion);
				AppendValue(platform.Reserved);
			}
		}
	}

	// ReSharper disable once CppParameterMayBeConstPtrOrRef
	// cannot be a const pointer, as the pointer value in the rule is not const
	void AppendValue(FW_OBJECT_METADATA* pMetadata)
	{
		if (!pMetadata)
		{
			AppendValue(L"null,");
			return;
		}

		const auto* enforcement_states = pMetadata->pEnforcementStates;
		const auto enforcement_states_count = pMetadata->dwNumEntries;

		AppendValue(pMetadata->qwFilterContextID);

		if (enforcement_states_count == 0 || !enforcement_states)
		{
			if (enforcement_states_count != 0 || enforcement_states)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& state : wil::make_range(enforcement_states, enforcement_states + enforcement_states_count))
			{
				AppendValue(state);
			}
		}
	}

	void AppendValue(const FW_NETWORK_NAMES& network_names)
	{
		const auto* names = network_names.wszNames;
		const auto names_count = network_names.dwNumEntries;

		if (names_count == 0 || !names)
		{
			if (names_count != 0 || names)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& name : wil::make_range(names, names + names_count))
			{
				AppendValue(name);
			}
		}
	}

	void AppendValue(const FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST& keyword_address_list)
	{
		const auto* keywords = keyword_address_list.ids;
		const auto keywords_count = keyword_address_list.dwNumIds;

		if (keywords_count == 0 || !keywords)
		{
			if (keywords_count != 0 || keywords)
			{
				DebugBreak();
			}
			AppendValue(0);
		}
		else
		{
			for (const auto& keyword : wil::make_range(keywords, keywords + keywords_count))
			{
				AppendValue(keyword);
			}
		}
	}

	void AppendValue(PCWSTR value)
	{
		if (!value || value[0] == L'\0')
		{
			normalizedRuleDetails.value.append(L"null,");
			return;
		}

		NormalizedString normalized_string = NormalizedString::Normalize(value);
		normalized_string.value += L',';

		normalizedRuleDetails += normalized_string;
	}

	void AppendValue(PWSTR value)
	{
		const PCWSTR const_value{ value };
		return AppendValue(const_value);
	}

	template <typename T>
	void AppendValue(T t)
	{
		// convert any integer type T
		const auto convertedValue = static_cast<uint64_t>(t);
		normalizedRuleDetails.value.append(std::to_wstring(convertedValue) + L',');
	}
};

// returns the same integer value as memcmp()
// -1 if lhs < rhs, 0 if equal, +1 if lhs > rhs
inline int RuleDetailsComparison(const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs.normalizedRuleDetails, rhs.normalizedRuleDetails);
}
