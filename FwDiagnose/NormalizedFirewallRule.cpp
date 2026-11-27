#include <format>
#include <span>
#include <string>

#include <windows.h>
#include <netfw.h>
#include <sddl.h>
#include "FwDiagnose.h"

#include "NormalizedFirewallRule.h"

#include <algorithm>
#include <ws2def.h>

namespace details
{
static WORD
MajorVersionFromSchemaVersion(WORD word) noexcept
{
	constexpr WORD MajorVersionOffset = 8;
	constexpr WORD MajorVersionBitMask = 0xFF00;
	return (word & MajorVersionBitMask) >> MajorVersionOffset;
}

static WORD
MinorVersionFromSchemaVersion(WORD word) noexcept
{
	constexpr WORD MinorVersionBitMask = 0x00FF;
	return word & MinorVersionBitMask;
}

static WORD
OSPlatformFromFWPlatform(FW_OS_PLATFORM platform)
{
	// trim off high-order FW bits to read the OS platform field that matches VER_PLATFORM_XXX values
	constexpr BYTE FWPlatformBitMask = 7;
	return platform.bPlatform & FWPlatformBitMask;
}

static std::wstring
ToString(FW_DIRECTION direction)
{
	switch (direction)
	{
	case FW_DIR_INVALID:
		return L"FW_DIR_INVALID";
	case FW_DIR_IN:
		return L"FW_DIR_IN";
	case FW_DIR_OUT:
		return L"FW_DIR_OUT";
	default:
		return L"(unknown FW_DIRECTION " + std::to_wstring(direction) + L")";
	}
}

static std::wstring
ToString(NET_FW_IP_PROTOCOL protocol)
{
	switch (protocol)
	{
	case NET_FW_IP_PROTOCOL_TCP:
		return L"NET_FW_IP_PROTOCOL_TCP";
	case NET_FW_IP_PROTOCOL_UDP:
		return L"NET_FW_IP_PROTOCOL_UDP";
	case NET_FW_IP_PROTOCOL_ANY:
		return L"NET_FW_IP_PROTOCOL_ANY";
	default:
		return std::to_wstring(protocol);
	}
}

static std::wstring
ToString(FW_RULE_ACTION action)
{
	switch (action)
	{
	case FW_RULE_ACTION_INVALID:
		return L"FW_RULE_ACTION_INVALID";
	case FW_RULE_ACTION_ALLOW_BYPASS:
		return L"FW_RULE_ACTION_ALLOW_BYPASS";
	case FW_RULE_ACTION_BLOCK:
		return L"FW_RULE_ACTION_BLOCK";
	case FW_RULE_ACTION_ALLOW:
		return L"FW_RULE_ACTION_ALLOW";
	default:
		return L"(unknown FW_RULE_ACTION " + std::to_wstring(action) + L")";
	}
}

static std::wstring
ToString(FW_OS_PLATFORM platform)
{
	std::wstring result;
	const auto os_platform = OSPlatformFromFWPlatform(platform);

	result += L"Platform: ";
	if (os_platform == VER_PLATFORM_WIN32s)
	{
		result += L"VER_PLATFORM_WIN32s";
	}
	else if (os_platform == VER_PLATFORM_WIN32_WINDOWS)
	{
		result += L"VER_PLATFORM_WIN32_WINDOWS";
	}
	else if (os_platform == VER_PLATFORM_WIN32_NT)
	{
		result += L"VER_PLATFORM_WIN32_NT";
	}
	else
	{
		result += L"(unknown platform " + std::to_wstring(platform.bPlatform) + L")";
	}

	result += L", Major Version: " + std::to_wstring(platform.bMajorVersion);
	result += L", Minor Version: " + std::to_wstring(platform.bMinorVersion);
	return result;
}

static std::wstring
ToString(FW_RULE_ORIGIN_TYPE type)
{
	switch (type)
	{
	case FW_RULE_ORIGIN_INVALID:
		return L"FW_RULE_ORIGIN_INVALID";
	case FW_RULE_ORIGIN_LOCAL:
		return L"FW_RULE_ORIGIN_LOCAL";
	case FW_RULE_ORIGIN_GP:
		return L"FW_RULE_ORIGIN_GP";
	case FW_RULE_ORIGIN_DYNAMIC:
		return L"FW_RULE_ORIGIN_DYNAMIC";
	case FW_RULE_ORIGIN_AUTOGEN:
		return L"FW_RULE_ORIGIN_AUTOGEN";
	case FW_RULE_ORIGIN_HARDCODED:
		return L"FW_RULE_ORIGIN_HARDCODED";
	case FW_RULE_ORIGIN_MDM:
		return L"FW_RULE_ORIGIN_MDM";
		// Hyper-V rule origins for host translated rules
	case FW_RULE_ORIGIN_HOST_LOCAL:
		return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_LOCAL)";
	case FW_RULE_ORIGIN_HOST_GP:
		return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_GP)";
	case FW_RULE_ORIGIN_HOST_DYNAMIC:
		return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_DYNAMIC)";
	case FW_RULE_ORIGIN_HOST_MDM:
		return L"HyperV-Firewall (FW_RULE_ORIGIN_HOST_MDM)";
	default:
		return L"(unknown FW_RULE_ORIGIN_TYPE " + std::to_wstring(type) + L")";
	}
}

static std::wstring
ToString(FW_RULE_FLAG flag)
{
	if (flag == FW_RULE_FLAGS_NONE)
	{
		return L"FW_RULE_FLAGS_NONE";
	}

	std::wstring result;
	if (flag & FW_RULE_FLAGS_ACTIVE)
	{
		result += L"FW_RULE_FLAGS_ACTIVE | ";
	}
	if (flag & FW_RULE_FLAGS_AUTHENTICATE)
	{
		result += L"FW_RULE_FLAGS_AUTHENTICATE | ";
	}
	if (flag & FW_RULE_FLAGS_AUTHENTICATE_WITH_ENCRYPTION)
	{
		result += L"FW_RULE_FLAGS_AUTHENTICATE_WITH_ENCRYPTION | ";
	}
	if (flag & FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE)
	{
		result += L"FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE | ";
	}
	if (flag & FW_RULE_FLAGS_LOOSE_SOURCE_MAPPED)
	{
		result += L"FW_RULE_FLAGS_LOOSE_SOURCE_MAPPED | ";
	}
	static_assert(FW_RULE_FLAGS_AUTOGENERATE_CONNECTION_SECURITY_RULE == FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION);
	if (flag & FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION)
	{
		result += L"FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION + FW_RULE_FLAGS_AUTOGENERATE_CONNECTION_SECURITY_RULE | ";
	}
	if (flag & FW_RULE_FLAGS_AUTH_WITH_ENC_NEGOTIATE)
	{
		result += L"FW_RULE_FLAGS_AUTH_WITH_ENC_NEGOTIATE | ";
	}
	if (flag & FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_APP)
	{
		result += L"FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_APP | ";
	}
	if (flag & FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_USER)
	{
		result += L"FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_USER | ";
	}
	if (flag & FW_RULE_FLAGS_AUTHENTICATE_BYPASS_OUTBOUND)
	{
		result += L"FW_RULE_FLAGS_AUTHENTICATE_BYPASS_OUTBOUND | ";
	}
	if (flag & FW_RULE_FLAGS_ALLOW_PROFILE_CROSSING)
	{
		result += L"FW_RULE_FLAGS_ALLOW_PROFILE_CROSSING | ";
	}
	if (flag & FW_RULE_FLAGS_LOCAL_ONLY_MAPPED)
	{
		result += L"FW_RULE_FLAGS_LOCAL_ONLY_MAPPED | ";
	}
	if (flag & FW_RULE_FLAGS_LUA_CONDITIONAL_ACE)
	{
		result += L"FW_RULE_FLAGS_LUA_CONDITIONAL_ACE | ";
	}
	if (flag & FW_RULE_FLAGS_BIND_TO_INTERFACE)
	{
		result += L"FW_RULE_FLAGS_BIND_TO_INTERFACE | ";
	}

	if (!result.empty())
	{
		// remove trailing " | "
		result.erase(result.size() - 3);
	}
	return result;
}

static std::wstring
ToString(FW_RULE_FLAGS2 flag)
{
	if (flag == FW_RULE_FLAGS2_NONE)
	{
		return L"FW_RULE_FLAGS2_NONE";
	}

	std::wstring result;

	if (flag & FW_RULE_FLAGS2_SYSTEMOS_ONLY)
	{
		result += L"FW_RULE_FLAGS2_SYSTEMOS_ONLY | ";
	}
	if (flag & FW_RULE_FLAGS2_GAMEOS_ONLY)
	{
		result += L"FW_RULE_FLAGS2_GAMEOS_ONLY | ";
	}
	if (flag & FW_RULE_FLAGS2_DEVMODE)
	{
		result += L"FW_RULE_FLAGS2_DEVMODE | ";
	}
	if (flag & FW_RULE_FLAGS2_EMPTY_REMOTENAME)
	{
		result += L"FW_RULE_FLAGS2_EMPTY_REMOTENAME | ";
	}
	if (flag & FW_RULE_FLAGS2_NOT_REMOTENAME)
	{
		result += L"FW_RULE_FLAGS2_NOT_REMOTENAME | ";
	}
	if (flag & FW_RULE_FLAGS2_CALLOUT_AND_AUDIT)
	{
		result += L"FW_RULE_FLAGS2_CALLOUT_AND_AUDIT | ";
	}
	if (flag & FW_RULE_FLAGS2_APP_LOOPBACK)
	{
		result += L"FW_RULE_FLAGS2_APP_LOOPBACK | ";
	}
	if (flag & FW_RULE_FLAGS2_INDIRECT_NAME_RESOLVED)
	{
		result += L"FW_RULE_FLAGS2_INDIRECT_NAME_RESOLVED | ";
	}
	if (flag & FW_RULE_FLAGS2_INDIRECT_DESCRIPTION_RESOLVED)
	{
		result += L"FW_RULE_FLAGS2_INDIRECT_DESCRIPTION_RESOLVED | ";
	}
	if (flag & FW_RULE_FLAGS2_DELAY_ENFORCE)
	{
		result += L"FW_RULE_FLAGS2_DELAY_ENFORCE | ";
	}
	if (flag & FW_RULE_FLAGS2_AVOID_NETID)
	{
		result += L"FW_RULE_FLAGS2_AVOID_NETID | ";
	}
	if (flag & FW_RULE_FLAGS2_LOOPBACK)
	{
		result += L"FW_RULE_FLAGS2_LOOPBACK | ";
	}
	if (flag & FW_RULE_FLAGS2_EDP)
	{
		result += L"FW_RULE_FLAGS2_EDP | ";
	}
	if (flag & FW_RULE_FLAGS2_TENANT_RESTRICTIONS_HIGH_WEIGHT)
	{
		result += L"FW_RULE_FLAGS2_TENANT_RESTRICTIONS_HIGH_WEIGHT | ";
	}

	if (!result.empty())
	{
		// remove trailing " | "
		result.erase(result.size() - 3);
	}
	return result;
}

static std::wstring
ExpandString(const std::wstring& original_filename)
{
	// resolve any environment variables in the string, then verify it exists
	std::wstring expanded_string;
	expanded_string.resize(original_filename.size() + 10, L' ');

	for (;;)
	{
		const auto expanded_size = ExpandEnvironmentStringsW(
		    original_filename.c_str(),
		    expanded_string.data(),
		    static_cast<DWORD>(expanded_string.size()));
		if (expanded_size == 0)
		{
			const auto gle = GetLastError();
			if (VerboseOutputEnabled())
			{
				std::printf(
				    "Failed to ExpandEnvironmentStrings(%ls) (0x%lx)",
				    original_filename.c_str(),
				    HRESULT_FROM_WIN32(gle));
			}
			expanded_string = {};
			break;
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

static bool
IsRuleAnAppxRule(const std::wstring& rule_name)
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

static void
ProcessForStringResource(std::wstring& string_value)
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
		if (VerboseOutputEnabled())
		{
			std::printf("Failed to expand the file name '%ls'\n", file_name.c_str());
		}
		return;
	}

	const wil::unique_hmodule file_name_hmod{
	    LoadLibraryExW(expanded_file_name.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE)};
	if (!file_name_hmod)
	{
		const auto gle = GetLastError();
		if (VerboseOutputEnabled())
		{
			std::printf("Failed to LoadLibraryExW(%ls) (0x%lx)\n", expanded_file_name.c_str(), HRESULT_FROM_WIN32(gle));
		}
		return;
	}

	uint32_t converted_value = 0;
	const auto conversion_error = wil::ResultFromException(
	    [&]
	    {
		    // strip the leading '-' from the string index if it exists
		    if (string_index.starts_with(L'-'))
		    {
			    string_index = string_index.substr(1, string_index.size() - 1);
		    }
		    converted_value = std::stoul(string_index);
	    });
	if (FAILED(conversion_error))
	{
		if (VerboseOutputEnabled())
		{
			std::printf(
			    "Failed to convert string index '%ls' to a number: 0x%lx\n",
			    string_index.c_str(),
			    conversion_error); // NOLINT(clang-diagnostic-format)
		}
		return;
	}

	// try to load the string resource
	PCWSTR raw_pointer_to_resource{nullptr};
	const auto conversion_size =
	    LoadStringW(file_name_hmod.get(), converted_value, reinterpret_cast<LPWSTR>(&raw_pointer_to_resource), 0);
	if (conversion_size == 0)
	{
		const auto gle = GetLastError();
		if (VerboseOutputEnabled())
		{
			std::printf(
			    "Failed to LoadStringW(%ls, %u) (0x%lx)\n",
			    expanded_file_name.c_str(),
			    converted_value,
			    HRESULT_FROM_WIN32(gle));
		}
		return;
	}

	std::wstring string_resource{raw_pointer_to_resource, raw_pointer_to_resource + conversion_size};
	string_value.swap(string_resource);
}

static bool
ContainsEnvironmentVariable(const std::wstring& path, std::span<const std::wstring_view> variables)
{
	// every variable starts with '%', so only those positions in the path can match
	for (auto offset = path.find(L'%'); offset != std::wstring::npos; offset = path.find(L'%', offset + 1))
	{
		const auto remaining_path_size = path.size() - offset;
		for (const auto variable : variables)
		{
			if (variable.size() > remaining_path_size)
			{
				continue;
			}

			constexpr BOOL ignore_case = TRUE;
			if (CompareStringOrdinal(
			        path.c_str() + offset,
			        static_cast<int>(variable.size()),
			        variable.data(),
			        static_cast<int>(variable.size()),
			        ignore_case) == CSTR_EQUAL)
			{
				return true;
			}
		}
	}
	return false;
}

// These variables expand differently for each account. The Firewall service (mpssvc) resolves rule paths as
// LocalService, so a path using one of them does not reach the file of the user who the path was intended for.
static bool
ContainsPerUserEnvironmentVariable(const std::wstring& path)
{
	constexpr std::wstring_view per_user_variables[]{L"%HOMEPATH%", L"%USERNAME%", L"%ONEDRIVE%"};
	return ContainsEnvironmentVariable(path, per_user_variables);
}

// These variables resolve within the profile of the Firewall service account. That can be deliberate, but may be
// unexpected, so a path using one is reported as a warning rather than as a broken rule.
static bool
ContainsServiceProfileEnvironmentVariable(const std::wstring& path)
{
	constexpr std::wstring_view
	    service_profile_variables[]{L"%USERPROFILE%", L"%APPDATA%", L"%LOCALAPPDATA%", L"%TEMP%", L"%TMP%"};
	return ContainsEnvironmentVariable(path, service_profile_variables);
}
} // namespace details

bool
RunningUnderWow64() noexcept
{
	static const bool running_under_wow64 = []() noexcept
	{
		BOOL is_wow64 = FALSE;
		return IsWow64Process(GetCurrentProcess(), &is_wow64) && is_wow64;
	}();
	return running_under_wow64;
}

NormalizedFirewallRule::NormalizedFirewallRule(const FW_RULE* fwRule, WORD requestedRuleVersion)
{
	fw_rule = fwRule;
	// we must store the version we requested, not the version in the rule
	// the FW_RULE* structure will be allocated based on the requested version
	// not the actual version of the rule
	requested_rule_version = requestedRuleVersion;

	if (fwRule->wszName)
	{
		std::wstring ruleName(fwRule->wszName);
		details::ProcessForStringResource(ruleName);
		rule_name = NormalizedString::Create(ruleName);
	}

	if (fwRule->wszDescription)
	{
		rule_description.assign(fwRule->wszDescription);
		details::ProcessForStringResource(rule_description);
	}
	if (fwRule->wszRuleId)
	{
		rule_id.assign(fwRule->wszRuleId);
	}

	// not tracking schema version to compare rules
	// if all other fields are equal, the schema version is not relevant to the rule being equal
	// AppendValue(fwRule->wSchemaVersion);

	// not tracking dwProfiles in the normalized rule
	// to allow comparing rules between profiles
	// AppendValue(fwRule->dwProfiles);

	AppendValue(fwRule->Direction);
	AppendValue(fwRule->wIpProtocol);
	// unnamed union for ports and ICMP types based on the IP Protocol
	switch (fwRule->wIpProtocol)
	{
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	{
		// read TCP and UDP ports
		AppendValue(fwRule->LocalPorts.wPortKeywords);
		AppendValue(fwRule->LocalPorts.Ports);
		AppendValue(fwRule->RemotePorts.wPortKeywords);
		AppendValue(fwRule->RemotePorts.Ports);
		break;
	}

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	{
		// read ICMP fields
		AppendValue(fwRule->V4TypeCodeList);
		AppendValue(fwRule->V6TypeCodeList);
		break;
	}

	// we don't have any other protocol-specific firewall rule properties
	default:
		AppendValue(0);
		break;
	}

	// not tracking the AddressKeywords or Addresses in the normalized rule
	// to allow comparing rules that want to ignore the keyword for local-subnet
	// AppendValue(fwRule->LocalAddresses.dwV4AddressKeywords);
	// AppendValue(fwRule->LocalAddresses.dwV6AddressKeywords);
	AppendValue(fwRule->LocalAddresses.V4SubNets);
	AppendValue(fwRule->LocalAddresses.V4Ranges);
	AppendValue(fwRule->LocalAddresses.V6SubNets);
	AppendValue(fwRule->LocalAddresses.V6Ranges);

	// not tracking the AddressKeywords or Addresses in the normalized rule
	// to allow comparing rules that want to ignore the keyword for local-subnet
	// AppendValue(fwRule->RemoteAddresses.dwV4AddressKeywords);
	// AppendValue(fwRule->RemoteAddresses.dwV6AddressKeywords);
	AppendValue(fwRule->RemoteAddresses.V4SubNets);
	AppendValue(fwRule->RemoteAddresses.V4Ranges);
	AppendValue(fwRule->RemoteAddresses.V6SubNets);
	AppendValue(fwRule->RemoteAddresses.V6Ranges);

	AppendValue(fwRule->LocalInterfaceIds);
	AppendValue(fwRule->dwLocalInterfaceTypes);
	AppendValue(fwRule->wszLocalApplication);
	CheckIfLocalApplicationExists();
	AppendValue(fwRule->wszLocalService);

	AppendValue(fwRule->Action);

	// not tracking wFlags in the normalized rule
	// to allow comparing rules regardless if they are enabled or disabled
	// AppendValue(fwRule->wFlags);
	is_rule_enabled = (fwRule->wFlags & FW_RULE_FLAGS_ACTIVE) == FW_RULE_FLAGS_ACTIVE;

	AppendValue(fwRule->wszRemoteMachineAuthorizationList);
	AppendValue(fwRule->wszRemoteUserAuthorizationList);
	AppendValue(fwRule->wszEmbeddedContext);
	AppendValue(fwRule->PlatformValidityList);

	AppendValue(fwRule->Status);
	AppendValue(fwRule->Origin);
	AppendValue(fwRule->wszGPOName);
	AppendValue(fwRule->Reserved);

	AppendValue(static_cast<const FW_OBJECT_METADATA*>(fwRule->pMetaData));

	AppendValue(fwRule->wszLocalUserAuthorizationList);
	AppendValue(fwRule->wszPackageId);
	AppendValue(fwRule->wszLocalUserOwner);
	ProcessLocalUserSid();

	AppendValue(fwRule->dwTrustTupleKeywords);
	AppendValue(fwRule->OnNetworkNames);
	AppendValue(fwRule->wszSecurityRealmId);
	AppendValue(fwRule->wFlags2);
	AppendValue(fwRule->RemoteOutServerNames);
	AppendValue(fwRule->wszFqbn);
	AppendValue(fwRule->compartmentId);

	if (!SupportsFieldsFromVersion(FW_BINARY_VERSION_31))
	{
		AppendValue(GUID{});  // FW_RULE::providerContextKey
		AppendValue(DWORD{}); // FW_RULE::FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST::dwNumIds
	}
	else
	{
		// fields are present in 2.31 and later
		AppendValue(fwRule->providerContextKey);
		AppendValue(fwRule->RemoteDynamicKeywordAddresses);
	}

	// nullptr when the field is not available, which matches a rule that has no package family name
	const auto package_family_name = PackageFamilyName();
	if (package_family_name)
	{
		auto temp_name = NormalizedString::Create(package_family_name);
		normalized_package_family_name.swap(temp_name);
	}
	AppendValue(package_family_name);
}

static std::wstring
AddressKeywordToString(DWORD keyword);
static std::wstring
PortKeywordToString(DWORD keyword);

namespace details
{
// Condition fields that are empty do not restrict the rule, so they print the effective policy rather than "(none)"
static std::wstring
NotRestrictedText(std::wstring_view scope)
{
	return std::format(L"(not restricted - {})", scope);
}

static std::wstring
ConditionTextToString(PCWSTR value, std::wstring_view scope)
{
	if (!value || *value == L'\0')
	{
		return NotRestrictedText(scope);
	}
	return value;
}

static bool
HasAddressEntries(const FW_ADDRESSES& addresses) noexcept
{
	return addresses.V4SubNets.dwNumEntries > 0 || addresses.V4Ranges.dwNumEntries > 0 ||
	       addresses.V6SubNets.dwNumEntries > 0 || addresses.V6Ranges.dwNumEntries > 0;
}

// The effective address restriction when a side has no subnets or ranges: keywords, then dynamic keyword addresses
// (remote side only), otherwise any address. Returns an empty string when subnets or ranges restrict the side.
static std::wstring
UnlistedAddressPolicyToString(const FW_ADDRESSES& addresses, DWORD dynamic_keyword_address_count)
{
	if (HasAddressEntries(addresses))
	{
		return {};
	}
	const DWORD keywords = addresses.dwV4AddressKeywords | addresses.dwV6AddressKeywords;
	if (keywords != FW_ADDRESS_KEYWORD_NONE)
	{
		return std::format(L"(set by address keywords: {})", AddressKeywordToString(keywords));
	}
	if (dynamic_keyword_address_count > 0)
	{
		return L"(set by dynamic keyword addresses)";
	}
	return NotRestrictedText(L"any address");
}
static std::wstring
SchemaVersionToString(WORD schema_version)
{
	return std::format(
	    L"{}.{}",
	    MajorVersionFromSchemaVersion(schema_version),
	    MinorVersionFromSchemaVersion(schema_version));
}

template <typename T>
static std::wstring
HexToString(T value)
{
	return std::format(L"0x{:x}", static_cast<uint64_t>(value));
}

static std::wstring
CountToString(DWORD count)
{
	return count == 0 ? std::wstring{FirewallRuleNoValueText} : std::to_wstring(count) + L" entries";
}

static std::wstring
AddressListToString(DWORD count, const FW_ADDRESSES& addresses, DWORD dynamic_keyword_address_count)
{
	if (count > 0)
	{
		return CountToString(count);
	}
	// an empty list only means "any address" when nothing else on that side restricts the address
	auto policy = UnlistedAddressPolicyToString(addresses, dynamic_keyword_address_count);
	return policy.empty() ? std::wstring{FirewallRuleNoValueText} : policy;
}

static std::wstring
PortsToString(const FW_PORT_RANGE_LIST& ports, PCWSTR empty_text)
{
	if (ports.dwNumEntries == 0 || !ports.pPorts)
	{
		return empty_text;
	}

	std::wstring result;
	for (DWORD i = 0; i < ports.dwNumEntries; ++i)
	{
		if (i > 0)
		{
			result += L", ";
		}
		result += std::to_wstring(ports.pPorts[i].wBegin);
		if (ports.pPorts[i].wBegin != ports.pPorts[i].wEnd)
		{
			result += L"-" + std::to_wstring(ports.pPorts[i].wEnd);
		}
	}
	return result;
}

static std::wstring
PortConditionToString(const FW_PORTS& ports)
{
	const auto unlisted_text =
	    ports.wPortKeywords != FW_PORT_KEYWORD_NONE
	        ? std::format(L"(set by port keywords: {})", PortKeywordToString(ports.wPortKeywords))
	        : NotRestrictedText(L"any port");
	return PortsToString(ports.Ports, unlisted_text.c_str());
}

static std::wstring
IcmpTypeCodesToString(const FW_ICMP_TYPE_CODE_LIST& type_codes, PCWSTR empty_text)
{
	if (type_codes.dwNumEntries == 0 || !type_codes.pEntries)
	{
		return empty_text;
	}

	std::wstring result;
	for (DWORD i = 0; i < type_codes.dwNumEntries; ++i)
	{
		if (i > 0)
		{
			result += L", ";
		}
		result += L"[type] " + std::to_wstring(type_codes.pEntries[i].bType) + L" - [code] " +
		          std::to_wstring(type_codes.pEntries[i].wCode);
	}
	return result;
}

static std::wstring
NetworkNamesToString(const FW_NETWORK_NAMES& names, std::wstring_view empty_text)
{
	if (names.dwNumEntries == 0 || !names.wszNames)
	{
		return std::wstring{empty_text};
	}

	std::wstring result;
	for (DWORD i = 0; i < names.dwNumEntries; ++i)
	{
		if (i > 0)
		{
			result += L", ";
		}
		result += FirewallRuleTextToString(names.wszNames[i]);
	}
	return result;
}

static std::wstring
GuidsToString(DWORD count, const GUID* guids, std::wstring_view empty_text)
{
	if (count == 0 || !guids)
	{
		return std::wstring{empty_text};
	}

	std::wstring result;
	for (DWORD i = 0; i < count; ++i)
	{
		if (i > 0)
		{
			result += L", ";
		}
		result += GuidToString(guids[i]);
	}
	return result;
}
} // namespace details

std::wstring
FirewallRuleTextToString(PCWSTR value)
{
	if (!value)
	{
		return FirewallRuleNoValueText;
	}
	if (*value == L'\0')
	{
		return FirewallRuleEmptyText;
	}
	return value;
}

std::wstring
NormalizedFirewallRule::FieldNotAvailableText() const
{
	// the readable fields are limited by whichever is older: the version the store was opened with or the rule's version
	return std::format(
	    L"(not available in schema version {})",
	    details::SchemaVersionToString(std::min(requested_rule_version, fw_rule->wSchemaVersion)));
}

// Prints every FW_RULE field in declaration order for every rule, so output has the same lines regardless of schema
// version: fields the rule's schema version cannot carry print FieldNotAvailableText(), fields the IP protocol does
// not use print a not-applicable placeholder, and empty fields print FirewallRuleNoValueText.
std::wstring
NormalizedFirewallRule::PrintRule() const
{
	if (!fw_rule)
	{
		return L"<NULL>\n";
	}

	std::wstring result;
	const auto append_line = [&](std::wstring_view label, std::wstring_view value)
	{
		result.append(label);
		result.append(L": ");
		result.append(value);
		result.append(L"\n");
	};

	append_line(L"Rule Name", FirewallRuleTextToString(fw_rule->wszName));
	append_line(L"Rule ID", FirewallRuleTextToString(fw_rule->wszRuleId));
	append_line(L"Description", FirewallRuleTextToString(fw_rule->wszDescription));
	append_line(L"Schema Version", details::SchemaVersionToString(fw_rule->wSchemaVersion));
	append_line(
	    L"Profiles",
	    fw_rule->dwProfiles == FW_PROFILE_TYPE_ALL
	        ? details::HexToString(fw_rule->dwProfiles) + L" " + details::NotRestrictedText(L"all profiles")
	        : details::HexToString(fw_rule->dwProfiles));
	append_line(L"Direction", details::ToString(fw_rule->Direction));
	append_line(L"IP Protocol", details::ToString(static_cast<NET_FW_IP_PROTOCOL>(fw_rule->wIpProtocol)));

	// ports and ICMP type/codes share a union in FW_RULE, so only the member that matches the protocol is valid
	constexpr WORD icmp_v4_protocol = 1;
	constexpr WORD icmp_v6_protocol = 58;
	const auto not_applicable = std::format(L"(not applicable to IP protocol {})", fw_rule->wIpProtocol);
	const bool uses_ports =
	    fw_rule->wIpProtocol == NET_FW_IP_PROTOCOL_TCP || fw_rule->wIpProtocol == NET_FW_IP_PROTOCOL_UDP;
	append_line(
	    L"Local Port Keywords",
	    uses_ports ? details::HexToString(fw_rule->LocalPorts.wPortKeywords) : not_applicable);
	append_line(L"Local Ports", uses_ports ? details::PortConditionToString(fw_rule->LocalPorts) : not_applicable);
	append_line(
	    L"Remote Port Keywords",
	    uses_ports ? details::HexToString(fw_rule->RemotePorts.wPortKeywords) : not_applicable);
	append_line(L"Remote Ports", uses_ports ? details::PortConditionToString(fw_rule->RemotePorts) : not_applicable);
	const auto any_icmp_type_code = details::NotRestrictedText(L"any ICMP type and code");
	append_line(
	    L"ICMP v4 Type/Code List",
	    fw_rule->wIpProtocol == icmp_v4_protocol
	        ? details::IcmpTypeCodesToString(fw_rule->V4TypeCodeList, any_icmp_type_code.c_str())
	        : not_applicable);
	append_line(
	    L"ICMP v6 Type/Code List",
	    fw_rule->wIpProtocol == icmp_v6_protocol
	        ? details::IcmpTypeCodesToString(fw_rule->V6TypeCodeList, any_icmp_type_code.c_str())
	        : not_applicable);

	const auto& local = fw_rule->LocalAddresses;
	const auto& remote = fw_rule->RemoteAddresses;
	const DWORD dynamic_keyword_address_count =
	    SupportsFieldsFromVersion(FW_BINARY_VERSION_31) ? fw_rule->RemoteDynamicKeywordAddresses.dwNumIds : 0;
	append_line(L"Local Address V4 Keywords", details::HexToString(local.dwV4AddressKeywords));
	append_line(L"Local Address V6 Keywords", details::HexToString(local.dwV6AddressKeywords));
	append_line(L"Local Address V4 Subnets", details::AddressListToString(local.V4SubNets.dwNumEntries, local, 0));
	append_line(L"Local Address V4 Ranges", details::AddressListToString(local.V4Ranges.dwNumEntries, local, 0));
	append_line(L"Local Address V6 Subnets", details::AddressListToString(local.V6SubNets.dwNumEntries, local, 0));
	append_line(L"Local Address V6 Ranges", details::AddressListToString(local.V6Ranges.dwNumEntries, local, 0));
	append_line(L"Remote Address V4 Keywords", details::HexToString(remote.dwV4AddressKeywords));
	append_line(L"Remote Address V6 Keywords", details::HexToString(remote.dwV6AddressKeywords));
	append_line(
	    L"Remote Address V4 Subnets",
	    details::AddressListToString(remote.V4SubNets.dwNumEntries, remote, dynamic_keyword_address_count));
	append_line(
	    L"Remote Address V4 Ranges",
	    details::AddressListToString(remote.V4Ranges.dwNumEntries, remote, dynamic_keyword_address_count));
	append_line(
	    L"Remote Address V6 Subnets",
	    details::AddressListToString(remote.V6SubNets.dwNumEntries, remote, dynamic_keyword_address_count));
	append_line(
	    L"Remote Address V6 Ranges",
	    details::AddressListToString(remote.V6Ranges.dwNumEntries, remote, dynamic_keyword_address_count));
	append_line(
	    L"Local Interface IDs",
	    details::GuidsToString(
	        fw_rule->LocalInterfaceIds.dwNumLUIDs,
	        fw_rule->LocalInterfaceIds.pLUIDs,
	        details::NotRestrictedText(L"all interfaces")));
	append_line(
	    L"Local Interface Types",
	    fw_rule->dwLocalInterfaceTypes == FW_INTERFACE_TYPE_ALL
	        ? details::HexToString(fw_rule->dwLocalInterfaceTypes) + L" " +
	              details::NotRestrictedText(L"all interface types")
	        : details::HexToString(fw_rule->dwLocalInterfaceTypes));
	append_line(L"Local Application", details::ConditionTextToString(fw_rule->wszLocalApplication, L"any application"));
	append_line(L"Local Service", details::ConditionTextToString(fw_rule->wszLocalService, L"any service"));

	append_line(L"Action", details::ToString(fw_rule->Action));
	append_line(
	    L"Flags",
	    details::ToString(static_cast<FW_RULE_FLAG>(fw_rule->wFlags)) + L" (" + details::HexToString(fw_rule->wFlags) +
	        L")");
	append_line(
	    L"Remote Machine Authorization List",
	    details::ConditionTextToString(fw_rule->wszRemoteMachineAuthorizationList, L"any remote machine"));
	append_line(
	    L"Remote User Authorization List",
	    details::ConditionTextToString(fw_rule->wszRemoteUserAuthorizationList, L"any remote user"));
	append_line(L"Embedded Context", FirewallRuleTextToString(fw_rule->wszEmbeddedContext));

	append_line(
	    L"Platform Validity List",
	    fw_rule->PlatformValidityList.dwNumEntries == 0
	        ? details::NotRestrictedText(L"all platforms")
	        : details::CountToString(fw_rule->PlatformValidityList.dwNumEntries));
	if (fw_rule->PlatformValidityList.pPlatforms)
	{
		for (DWORD i = 0; i < fw_rule->PlatformValidityList.dwNumEntries; ++i)
		{
			result += L"  - " + details::ToString(fw_rule->PlatformValidityList.pPlatforms[i]) + L"\n";
		}
	}

	append_line(
	    L"Status",
	    fw_rule->Status == FW_RULE_STATUS_OK ? std::wstring{L"FW_RULE_STATUS_OK"}
	                                         : std::format(L"0x{:08X}", static_cast<uint32_t>(fw_rule->Status)));
	append_line(L"Origin", details::ToString(fw_rule->Origin));
	append_line(L"GPO Name", FirewallRuleTextToString(fw_rule->wszGPOName));
	append_line(
	    L"MetaData",
	    fw_rule->pMetaData ? details::CountToString(fw_rule->pMetaData->dwNumEntries) : FirewallRuleNoValueText);
	append_line(
	    L"Local User Authorization List",
	    details::ConditionTextToString(fw_rule->wszLocalUserAuthorizationList, L"any local user"));
	append_line(L"Package ID", details::ConditionTextToString(fw_rule->wszPackageId, L"any package"));
	append_line(L"Local User Owner", details::ConditionTextToString(fw_rule->wszLocalUserOwner, L"all users"));
	append_line(L"Trust Tuple Keywords", details::HexToString(fw_rule->dwTrustTupleKeywords));
	append_line(
	    L"Network Names",
	    details::NetworkNamesToString(fw_rule->OnNetworkNames, details::NotRestrictedText(L"any network")));
	append_line(
	    L"Security Realm ID",
	    details::ConditionTextToString(fw_rule->wszSecurityRealmId, L"any security realm"));
	append_line(
	    L"Flags2",
	    details::ToString(static_cast<FW_RULE_FLAGS2>(fw_rule->wFlags2)) + L" (" +
	        details::HexToString(fw_rule->wFlags2) + L")");
	append_line(
	    L"Remote Out Server Names",
	    details::NetworkNamesToString(fw_rule->RemoteOutServerNames, details::NotRestrictedText(L"any server name")));
	append_line(L"FQBN", details::ConditionTextToString(fw_rule->wszFqbn, L"any binary"));
	append_line(L"Compartment ID", std::to_wstring(fw_rule->compartmentId));

	if (SupportsFieldsFromVersion(FW_BINARY_VERSION_31))
	{
		constexpr GUID null_guid{};
		append_line(
		    L"Provider Context Key",
		    fw_rule->providerContextKey == null_guid ? std::wstring{FirewallRuleNoValueText}
		                                             : GuidToString(fw_rule->providerContextKey));
		append_line(
		    L"Remote Dynamic Keyword Address IDs",
		    details::GuidsToString(
		        fw_rule->RemoteDynamicKeywordAddresses.dwNumIds,
		        fw_rule->RemoteDynamicKeywordAddresses.ids,
		        L"(not restricted by dynamic keyword addresses)"));
	}
	else
	{
		append_line(L"Provider Context Key", FieldNotAvailableText());
		append_line(L"Remote Dynamic Keyword Address IDs", FieldNotAvailableText());
	}

	append_line(
	    L"Package Family Name",
	    SupportsFieldsFromVersion(FW_BINARY_VERSION_33)
	        ? details::ConditionTextToString(fw_rule->wszPackageFamilyName, L"any package family")
	        : FieldNotAvailableText());

	return result;
}

bool
NormalizedFirewallRule::RuleTargetsLocalUser() const
{
	return fw_rule->wszLocalUserAuthorizationList && *fw_rule->wszLocalUserAuthorizationList != L'\0';
}

bool
NormalizedFirewallRule::RuleTargetsNtService() const
{
	return fw_rule->wszLocalService != nullptr && fw_rule->wszLocalService[0] != L'\0';
}

bool
NormalizedFirewallRule::RuleTargetsLocalNonSystemApplication() const
{
	if (fw_rule->wszLocalApplication)
	{
		return !RuleTargetsLocalSystemApplication();
	}
	const auto package_family_name = PackageFamilyName();
	return (package_family_name && *package_family_name != L'\0') ||
	       (fw_rule->wszPackageId && *fw_rule->wszPackageId != L'\0');
}

bool
NormalizedFirewallRule::RuleTargetsLocalSystemApplication() const
{
	if (fw_rule->wszLocalApplication && fw_rule->wszLocalApplication[0] != L'\0')
	{
		return NormalizedString::StringCompare(L"system", fw_rule->wszLocalApplication) == 0;
	}
	return false;
}

bool
NormalizedFirewallRule::RuleTargetsLocalAppxRuleApplication() const
{
	if (fw_rule->wszLocalApplication && fw_rule->wszLocalApplication[0] != L'\0')
	{
		return details::IsRuleAnAppxRule(fw_rule->wszLocalApplication);
	}
	return false;
}

void
NormalizedFirewallRule::ReportListWithNoEntries(PCSTR list_description) const
{
	// the full rule cannot be printed here, as PrintRule reads the same list
	std::printf(
	    "  ** Firewall rule has a %hs with an entry count > 0 but no entries - treating it as empty. Rule Name: %ls, "
	    "RuleId: %ls\n",
	    list_description,
	    rule_name.value.c_str(),
	    rule_id.c_str());
}

void
NormalizedFirewallRule::CheckIfLocalApplicationExists()
{
	if (!fw_rule->wszLocalApplication || fw_rule->wszLocalApplication[0] == L'\0')
	{
		return;
	}
	if (RuleTargetsLocalSystemApplication())
	{
		// "System" identifies the kernel - it is not a file path
		return;
	}
	if (RuleTargetsLocalAppxRuleApplication())
	{
		// appx rules must be checked using appx APIs to check for that package
		return;
	}

	const std::wstring original_filename{fw_rule->wszLocalApplication};
	if (details::ContainsPerUserEnvironmentVariable(original_filename))
	{
		local_application_exists = false;
		local_application_uses_per_user_variable = true;
		local_application_failure_string = "Contains per-user environment variable";
		return;
	}
	if (details::ContainsServiceProfileEnvironmentVariable(original_filename))
	{
		// this expands differently for this process than for the Firewall service, so the file cannot be checked here
		local_application_uses_service_profile_variable = true;
		return;
	}
	if (RunningUnderWow64())
	{
		// file system and environment redirection would make existing files look like they do not exist
		return;
	}

	const auto expanded_string = details::ExpandString(original_filename);
	if (expanded_string.empty())
	{
		// failed to expand the string, cannot check if it exists
		return;
	}

	// now check if the file exists
	WIN32_FIND_DATA find_data{};
	HANDLE found_file =
	    FindFirstFileExW(expanded_string.c_str(), FindExInfoBasic, &find_data, FindExSearchNameMatch, nullptr, 0);
	if (found_file == INVALID_HANDLE_VALUE)
	{
		const auto gle = GetLastError();
		if (DebugOutputEnabled())
		{
			std::printf("Failed to FindFirstFileExW(%ls) (0x%lx)\n", expanded_string.c_str(), HRESULT_FROM_WIN32(gle));
		}

		local_application_exists = false;
		local_application_lookup_error = HRESULT_FROM_WIN32(gle);
		local_application_failure_string =
		    std::format("Failed to find the file (0x{:x})", static_cast<uint32_t>(local_application_lookup_error));
	}

	else
	{
		local_application_exists = true;
		FindClose(found_file);
	}
}

void
NormalizedFirewallRule::ProcessLocalUserSid()
{
	if (!fw_rule->wszLocalUserOwner || fw_rule->wszLocalUserOwner[0] == L'\0')
	{
		return;
	}

	// process the local user owner string for string resources
	wil::unique_sid localUserOwnerSid;
	if (!ConvertStringSidToSid(fw_rule->wszLocalUserOwner, localUserOwnerSid.addressof()))
	{
		const auto gle = GetLastError();
		if (VerboseOutputEnabled())
		{
			std::printf(
			    "Failed to ConvertStringSidToSid(%ls) (0x%lx)\n",
			    fw_rule->wszLocalUserOwner,
			    HRESULT_FROM_WIN32(gle));
		}
		successfully_resolved_user_name = false;
		resolve_name_failure_string = std::format(
		    " Failed to convert string SID to SID (0x{:x}) ",
		    static_cast<uint32_t>(HRESULT_FROM_WIN32(gle)));
		return;
	}

	DWORD localUserOwnerNameSize = 0;
	DWORD cchReferencedDomainName = 0;
	SID_NAME_USE sid_name_use{SidTypeUnknown};
	if (!LookupAccountSidW(
	        nullptr,
	        localUserOwnerSid.get(),
	        local_user_owner_name.data(),
	        &localUserOwnerNameSize,
	        local_user_domain_name.data(),
	        &cchReferencedDomainName,
	        &sid_name_use))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			local_user_owner_name.resize(localUserOwnerNameSize);
			local_user_domain_name.resize(cchReferencedDomainName);

			if (!LookupAccountSidW(
			        nullptr,
			        localUserOwnerSid.get(),
			        local_user_owner_name.data(),
			        &localUserOwnerNameSize,
			        local_user_domain_name.data(),
			        &cchReferencedDomainName,
			        &sid_name_use))
			{
				const auto gle = GetLastError();
				if (DebugOutputEnabled())
				{
					std::printf(
					    "Failed to LookupAccountSid(%ls) (0x%lx)\n",
					    fw_rule->wszLocalUserOwner,
					    HRESULT_FROM_WIN32(gle));
				}

				successfully_resolved_user_name = false;
				resolve_name_failure_string = std::format(
				    " Failed to lookup account SID (0x{:x}) ",
				    static_cast<uint32_t>(HRESULT_FROM_WIN32(gle)));
				return;
			}

			// on success, the sizes exclude the null terminator that the first call included
			local_user_owner_name.resize(localUserOwnerNameSize);
			local_user_domain_name.resize(cchReferencedDomainName);
			successfully_resolved_user_name = true;

			if (DebugOutputEnabled())
			{
				if (local_user_domain_name.empty())
				{
					std::printf(
					    "Successfully converted LocalUserOwner SID %ls to %ls\n",
					    fw_rule->wszLocalUserOwner,
					    local_user_owner_name.c_str());
				}
				else
				{
					std::printf(
					    "Successfully converted LocalUserOwner SID %ls to %ls\\%ls\n",
					    fw_rule->wszLocalUserOwner,
					    local_user_domain_name.c_str(),
					    local_user_owner_name.c_str());
				}
			}
		}
		else
		{
			const auto gle = GetLastError();
			if (DebugOutputEnabled())
			{
				std::printf(
				    "Failed to LookupAccountSid(%ls) (0x%lx)\n",
				    fw_rule->wszLocalUserOwner,
				    HRESULT_FROM_WIN32(gle));
			}

			successfully_resolved_user_name = false;
			resolve_name_failure_string =
			    std::format(" Failed to lookup account SID (0x{:x}) ", static_cast<uint32_t>(HRESULT_FROM_WIN32(gle)));
		}
	}
	else
	{
		// should never happen
		FAIL_FAST();
	}
}

void
NormalizedFirewallRule::AppendValue(const GUID& guid)
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

// sort the port range so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_PORT_RANGE_LIST& list)
{
	const auto* ports = list.pPorts;
	const auto ports_count = list.dwNumEntries;
	if (ports_count == 0 || !ports)
	{
		if (ports_count != 0 && !ports)
		{
			ReportListWithNoEntries("port list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(ports_count);
		std::vector sorted_ports(ports, ports + ports_count);
		std::ranges::sort(
		    sorted_ports,
		    [](const FW_PORT_RANGE& a, const FW_PORT_RANGE& b)
		    {
			    if (a.wBegin != b.wBegin)
			    {
				    return a.wBegin < b.wBegin;
			    }
			    return a.wEnd < b.wEnd;
		    });
		for (const auto& port : sorted_ports)
		{
			AppendValue(port.wBegin);
			AppendValue(port.wEnd);
		}
	}
}

// sort the ICMP range list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_ICMP_TYPE_CODE_LIST& list)
{
	const auto* icmp_list = list.pEntries;
	const auto icmp_count = list.dwNumEntries;
	if (icmp_count == 0 || !icmp_list)
	{
		if (icmp_count != 0 && !icmp_list)
		{
			ReportListWithNoEntries("ICMP type and code list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(icmp_count);
		std::vector sorted_icmp(icmp_list, icmp_list + icmp_count);
		std::ranges::sort(
		    sorted_icmp,
		    [](const FW_ICMP_TYPE_CODE& a, const FW_ICMP_TYPE_CODE& b)
		    {
			    if (a.bType != b.bType)
			    {
				    return a.bType < b.bType;
			    }
			    return a.wCode < b.wCode;
		    });
		for (const auto& icmp : sorted_icmp)
		{
			AppendValue(icmp.bType);
			AppendValue(icmp.wCode);
		}
	}
}

// sort the IP range list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_IPV4_SUBNET_LIST& list)
{
	const auto* subnets = list.pSubNets;
	const auto subnet_count = list.dwNumEntries;
	if (subnet_count == 0 || !subnets)
	{
		if (subnet_count != 0 && !subnets)
		{
			ReportListWithNoEntries("IPv4 subnet list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(subnet_count);
		std::vector sorted_subnets(subnets, subnets + subnet_count);
		std::ranges::sort(
		    sorted_subnets,
		    [](const FW_IPV4_SUBNET& a, const FW_IPV4_SUBNET& b)
		    {
			    if (a.dwAddress != b.dwAddress)
			    {
				    return a.dwAddress < b.dwAddress;
			    }
			    return a.dwSubNetMask < b.dwSubNetMask;
		    });
		for (const auto& subnet : sorted_subnets)
		{
			AppendValue(subnet.dwAddress);
			AppendValue(subnet.dwSubNetMask);
		}
	}
}

// sort the IP range list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_IPV6_SUBNET_LIST& list)
{
	const auto* subnets = list.pSubNets;
	const auto subnet_count = list.dwNumEntries;
	if (subnet_count == 0 || !subnets)
	{
		if (subnet_count != 0 && !subnets)
		{
			ReportListWithNoEntries("IPv6 subnet list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(subnet_count);
		std::vector sorted_subnets(subnets, subnets + subnet_count);
		std::ranges::sort(
		    sorted_subnets,
		    [](const FW_IPV6_SUBNET& a, const FW_IPV6_SUBNET& b)
		    {
			    const auto cmp = std::memcmp(a.Address, b.Address, sizeof(a.Address));
			    if (cmp != 0)
			    {
				    return cmp < 0;
			    }
			    return a.dwNumPrefixBits < b.dwNumPrefixBits;
		    });
		for (const auto& subnet : sorted_subnets)
		{
			// append as 2 64-bit integers
			static_assert(sizeof(subnet.Address) == 2 * sizeof(uint64_t));
			const BYTE* address_buffer = subnet.Address;
			const uint64_t* first_integer = reinterpret_cast<const uint64_t*>(address_buffer);
			AppendValue(*first_integer);
			const uint64_t* second_integer = reinterpret_cast<const uint64_t*>(address_buffer + sizeof(uint64_t));
			AppendValue(*second_integer);
			AppendValue(subnet.dwNumPrefixBits);
		}
	}
}

// sort the IP range list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_IPV4_RANGE_LIST& list)
{
	const auto* ranges = list.pRanges;
	const auto range_count = list.dwNumEntries;
	if (range_count == 0 || !ranges)
	{
		if (range_count != 0 && !ranges)
		{
			ReportListWithNoEntries("IPv4 range list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(range_count);
		std::vector sorted_ranges(ranges, ranges + range_count);
		std::ranges::sort(
		    sorted_ranges,
		    [](const FW_IPV4_ADDRESS_RANGE& a, const FW_IPV4_ADDRESS_RANGE& b)
		    {
			    if (a.dwBegin != b.dwBegin)
			    {
				    return a.dwBegin < b.dwBegin;
			    }
			    return a.dwEnd < b.dwEnd;
		    });
		for (const auto& range : sorted_ranges)
		{
			AppendValue(range.dwBegin);
			AppendValue(range.dwEnd);
		}
	}
}

void
NormalizedFirewallRule::AppendValue(const FW_IPV6_RANGE_LIST& list)
{
	const auto* ranges = list.pRanges;
	const auto range_count = list.dwNumEntries;
	if (range_count == 0 || !ranges)
	{
		if (range_count != 0 && !ranges)
		{
			ReportListWithNoEntries("IPv6 range list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(range_count);
		std::vector sorted_ranges(ranges, ranges + range_count);
		std::ranges::sort(
		    sorted_ranges,
		    [](const FW_IPV6_ADDRESS_RANGE& a, const FW_IPV6_ADDRESS_RANGE& b)
		    {
			    const auto cmp = std::memcmp(a.Begin, b.Begin, sizeof(a.Begin));
			    if (cmp != 0)
			    {
				    return cmp < 0;
			    }
			    return std::memcmp(a.End, b.End, sizeof(a.End)) < 0;
		    });
		for (const auto& range : sorted_ranges)
		{
			// append as 2 64-bit integers
			static_assert(sizeof(range.Begin) == 2 * sizeof(uint64_t));
			const BYTE* begin_buffer = range.Begin;
			const uint64_t* first_begin_integer = reinterpret_cast<const uint64_t*>(begin_buffer);
			AppendValue(*first_begin_integer);
			const uint64_t* second_begin_integer =
			    reinterpret_cast<const uint64_t*>(begin_buffer + sizeof(first_begin_integer));
			AppendValue(*second_begin_integer);
			// append as 2 64-bit integers
			static_assert(sizeof(range.End) == 2 * sizeof(uint64_t));
			const BYTE* end_buffer = range.End;
			const uint64_t* first_end_integer = reinterpret_cast<const uint64_t*>(end_buffer);
			AppendValue(*first_end_integer);
			const uint64_t* second_end_integer =
			    reinterpret_cast<const uint64_t*>(end_buffer + sizeof(first_end_integer));
			AppendValue(*second_end_integer);
		}
	}
}

// sort the interface LUIDs so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_INTERFACE_LUIDS& interface_luids)
{
	const auto* luids = interface_luids.pLUIDs;
	const auto luids_count = interface_luids.dwNumLUIDs;
	if (luids_count == 0 || !luids)
	{
		if (luids_count != 0 && !luids)
		{
			ReportListWithNoEntries("interface LUID list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(luids_count);
		std::vector sorted_luids(luids, luids + luids_count);
		std::ranges::sort(
		    sorted_luids,
		    [](const GUID& a, const GUID& b)
		    {
			    return memcmp(&a, &b, sizeof(GUID)) < 0;
		    });
		for (const auto& luid : sorted_luids)
		{
			AppendValue(luid);
		}
	}
}

// sort the platform list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_OS_PLATFORM_LIST& list)
{
	const auto* platforms = list.pPlatforms;
	const auto platform_count = list.dwNumEntries;
	if (platform_count == 0 || !platforms)
	{
		if (platform_count != 0 && !platforms)
		{
			ReportListWithNoEntries("OS platform list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(platform_count);
		std::vector sorted_platforms(platforms, platforms + platform_count);
		std::ranges::sort(
		    sorted_platforms,
		    [](const FW_OS_PLATFORM& a, const FW_OS_PLATFORM& b)
		    {
			    if (a.bPlatform != b.bPlatform)
			    {
				    return a.bPlatform < b.bPlatform;
			    }
			    if (a.bMajorVersion != b.bMajorVersion)
			    {
				    return a.bMajorVersion < b.bMajorVersion;
			    }
			    if (a.bMinorVersion != b.bMinorVersion)
			    {
				    return a.bMinorVersion < b.bMinorVersion;
			    }
			    return a.Reserved < b.Reserved;
		    });
		for (const auto& platform : sorted_platforms)
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
// sort the object metadata list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_OBJECT_METADATA* pMetadata)
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
		if (enforcement_states_count != 0 && !enforcement_states)
		{
			ReportListWithNoEntries("metadata enforcement state list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(enforcement_states_count);
		std::vector sorted_states(enforcement_states, enforcement_states + enforcement_states_count);
		std::ranges::sort(sorted_states);
		for (const auto& state : sorted_states)
		{
			AppendValue(state);
		}
	}
}

// sort the network names list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_NETWORK_NAMES& network_names)
{
	const auto* names = network_names.wszNames;
	const auto names_count = network_names.dwNumEntries;

	if (names_count == 0 || !names)
	{
		if (names_count != 0 && !names)
		{
			ReportListWithNoEntries("network name list");
		}
		AppendValue(0);
	}
	else
	{
		AppendValue(names_count);
		std::vector sorted_names(names, names + names_count);
		std::ranges::sort(
		    sorted_names,
		    [](const LPWSTR& a, const LPWSTR& b)
		    {
			    return NormalizedString::StringCompare(a, b) < 0;
		    });
		for (const auto& name : sorted_names)
		{
			AppendValue(name);
		}
	}
}

// sort the dynamic keyword list so we can find duplicates even if they are in different order
void
NormalizedFirewallRule::AppendValue(const FW_RULE::FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST& list)
{
	const auto* ids = list.ids;
	const auto ids_count = list.dwNumIds;
	if (ids_count == 0 || !ids)
	{
		if (ids_count != 0 && !ids)
		{
			ReportListWithNoEntries("dynamic keyword address ID list");
		}

		AppendValue(0); // for the count
	}
	else
	{
		AppendValue(ids_count);
		for (const auto& id : wil::make_range(ids, ids + ids_count))
		{
			AppendValue(id);
		}
	}
}

static std::wstring
AddressKeywordToString(DWORD keyword)
{
	FW_ADDRESS_KEYWORD address_keyword = static_cast<FW_ADDRESS_KEYWORD>(keyword);

	if (address_keyword == FW_ADDRESS_KEYWORD_NONE)
	{
		return L"None";
	}

	std::wstring result;
	if (address_keyword & FW_ADDRESS_KEYWORD_LOCAL_SUBNET)
	{
		result += L"LocalSubnet ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_DNS)
	{
		result += L"DNS ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_DHCP)
	{
		result += L"DHCP ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_WINS)
	{
		result += L"WINS ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_DEFAULT_GATEWAY)
	{
		result += L"DefaultGateway ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_INTRANET)
	{
		result += L"Intranet ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_INTERNET)
	{
		result += L"Internet ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_PLAYTO_RENDERERS)
	{
		result += L"PlayToRenderers ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_REMOTE_INTRANET)
	{
		result += L"RemoteIntranet ";
	}
	if (address_keyword & FW_ADDRESS_KEYWORD_CAPTIVE_PORTAL)
	{
		result += L"CaptivePortal ";
	}
	if (!result.empty())
	{
		// strip off the trailing space
		result.pop_back();
	}

	if (result.empty())
	{
		result = L"<Unknown FW_ADDRESS_KEYWORD> " + std::to_wstring(address_keyword);
	}
	return result;
}

static bool
IsAnyAddressSpecified(const FW_RULE* fw_rule) noexcept
{
	return fw_rule->LocalAddresses.V4Ranges.dwNumEntries > 0 || fw_rule->LocalAddresses.V4SubNets.dwNumEntries > 0 ||
	       fw_rule->LocalAddresses.V6Ranges.dwNumEntries > 0 || fw_rule->LocalAddresses.V6SubNets.dwNumEntries > 0 ||
	       fw_rule->RemoteAddresses.V4Ranges.dwNumEntries > 0 || fw_rule->RemoteAddresses.V4SubNets.dwNumEntries > 0 ||
	       fw_rule->RemoteAddresses.V6Ranges.dwNumEntries > 0 || fw_rule->RemoteAddresses.V6SubNets.dwNumEntries > 0;
}

static std::wstring
PortKeywordToString(DWORD keyword)
{
	FW_PORT_KEYWORD port_keyword = static_cast<FW_PORT_KEYWORD>(keyword);

	if (port_keyword == FW_PORT_KEYWORD_NONE)
	{
		return L"None";
	}

	std::wstring result;
	if (port_keyword & FW_PORT_KEYWORD_DYNAMIC_RPC_PORTS)
	{
		result += L"DynamicRpcPorts ";
	}
	if (port_keyword & FW_PORT_KEYWORD_RPC_EP)
	{
		result += L"RpcEphemeralPorts ";
	}
	if (port_keyword & FW_PORT_KEYWORD_TEREDO_PORT)
	{
		result += L"TeredoPort ";
	}
	if (port_keyword & FW_PORT_KEYWORD_IP_TLS_IN)
	{
		result += L"IpTlsIn ";
	}
	if (port_keyword & FW_PORT_KEYWORD_IP_TLS_OUT)
	{
		result += L"IpTlsOut ";
	}
	if (port_keyword & FW_PORT_KEYWORD_DHCP)
	{
		result += L"Dhcp ";
	}
	if (port_keyword & FW_PORT_KEYWORD_PLAYTO_DISCOVERY)
	{
		result += L"PlayToDiscovery ";
	}
	if (port_keyword & FW_PORT_KEYWORD_MDNS)
	{
		result += L"Mdns ";
	}
	if (port_keyword & FW_PORT_KEYWORD_CORTANA_OUT)
	{
		result += L"CortanaOut ";
	}
	if (port_keyword & FW_PORT_KEYWORD_PROXIMAL_TCP_CDP)
	{
		result += L"ProximalTcpCdp ";
	}

	if (!result.empty())
	{
		// strip off the trailing space
		result.pop_back();
	}

	if (result.empty())
	{
		result = L"<Unknown FW_PORT_KEYWORD> " + std::to_wstring(port_keyword);
	}
	return result;
}

// Prints the same lines for every rule: fields that are empty print a placeholder, fields the rule's schema version
// cannot carry print NormalizedFirewallRule::FieldNotAvailableText(), and fields the IP protocol does not use print a
// not-applicable placeholder (ports and ICMP type/codes share a union in FW_RULE, so only one of them is valid).
std::wstring
PrintRuleContents(const NormalizedFirewallRule& rule_details, size_t counter)
{
	const auto* fw_rule = rule_details.fw_rule;
	std::wstring return_string = std::format(
	    L"       {} : Rule Name: {}\n",
	    counter,
	    rule_details.rule_name.value.empty() ? L"<empty>" : rule_details.rule_name.value);
	const auto append_line = [&](std::wstring_view label, std::wstring_view value)
	{
		return_string.append(std::format(L"           {}: {}\n", label, value));
	};

	append_line(
	    L"Description",
	    rule_details.rule_description.empty() ? std::wstring{FirewallRuleNoValueText} : rule_details.rule_description);

	if (rule_details.missing_package_family_name || rule_details.missing_package_id)
	{
		return_string.append(L"           Inbound rule targeting an application that is not installed\n");
	}

	append_line(L"Local Service", details::ConditionTextToString(fw_rule->wszLocalService, L"any service"));
	append_line(L"Application", details::ConditionTextToString(fw_rule->wszLocalApplication, L"any application"));
	append_line(
	    L"Package Family Name",
	    rule_details.SupportsFieldsFromVersion(FW_BINARY_VERSION_33)
	        ? details::ConditionTextToString(fw_rule->wszPackageFamilyName, L"any package family")
	        : rule_details.FieldNotAvailableText());
	append_line(L"Package ID", details::ConditionTextToString(fw_rule->wszPackageId, L"any package"));

	if (rule_details.successfully_resolved_user_name.value_or(false))
	{
		append_line(
		    L"User",
		    std::format(
		        L"{}\\{}",
		        rule_details.local_user_domain_name.empty() ? L"<empty>" : rule_details.local_user_domain_name,
		        rule_details.local_user_owner_name.empty() ? L"<empty>" : rule_details.local_user_owner_name));
	}
	else if (!fw_rule->wszLocalUserOwner || fw_rule->wszLocalUserOwner[0] == L'\0')
	{
		append_line(L"User", details::NotRestrictedText(L"all users"));
	}
	else
	{
		append_line(L"User", std::format(L"{} (not resolved)", fw_rule->wszLocalUserOwner));
	}
	append_line(
	    L"Local User Authorization List",
	    details::ConditionTextToString(fw_rule->wszLocalUserAuthorizationList, L"any local user"));

	// keywords are the restriction when a side has no subnets or ranges; otherwise both apply
	const auto address_constraints_to_string = [](const FW_ADDRESSES& addresses, DWORD dynamic_keyword_address_count)
	{
		if (!details::HasAddressEntries(addresses) && addresses.dwV4AddressKeywords == FW_ADDRESS_KEYWORD_NONE &&
		    addresses.dwV6AddressKeywords == FW_ADDRESS_KEYWORD_NONE)
		{
			return details::UnlistedAddressPolicyToString(addresses, dynamic_keyword_address_count);
		}
		return std::format(
		    L"IPv4 ({}) IPv6 ({})",
		    AddressKeywordToString(addresses.dwV4AddressKeywords),
		    AddressKeywordToString(addresses.dwV6AddressKeywords));
	};
	const DWORD dynamic_keyword_address_count = rule_details.SupportsFieldsFromVersion(FW_BINARY_VERSION_31)
	                                                ? fw_rule->RemoteDynamicKeywordAddresses.dwNumIds
	                                                : 0;
	append_line(L"Local Addresses Constraints", address_constraints_to_string(fw_rule->LocalAddresses, 0));
	append_line(
	    L"Remote Addresses Constraints",
	    address_constraints_to_string(fw_rule->RemoteAddresses, dynamic_keyword_address_count));
	append_line(
	    L"Target Address Constraints",
	    IsAnyAddressSpecified(fw_rule) ? L"address subnets or ranges are specified"
	                                   : L"(not restricted by address subnets or ranges)");

	const auto protocol = fw_rule->wIpProtocol;
	const bool uses_ports = protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
	std::wstring protocol_string;
	switch (protocol)
	{
	case IPPROTO_TCP:
		protocol_string = L"TCP";
		break;
	case IPPROTO_UDP:
		protocol_string = L"UDP";
		break;
	case IPPROTO_ICMP:
		protocol_string = L"ICMPv4";
		break;
	case IPPROTO_ICMPV6:
		protocol_string = L"ICMPv6";
		break;
	case FW_IP_PROTOCOL_ANY:
		protocol_string = L"any protocol";
		break;
	default:
		protocol_string = L"IP protocol " + std::to_wstring(protocol);
		break;
	}
	const auto not_applicable = std::format(L"(not applicable to {})", protocol_string);

	append_line(
	    L"Protocol",
	    protocol == FW_IP_PROTOCOL_ANY ? details::NotRestrictedText(L"any protocol") : protocol_string);
	append_line(
	    L"Local Port Constraints",
	    uses_ports ? PortKeywordToString(fw_rule->LocalPorts.wPortKeywords) : not_applicable);
	append_line(
	    L"Remote Port Constraints",
	    uses_ports ? PortKeywordToString(fw_rule->RemotePorts.wPortKeywords) : not_applicable);
	append_line(L"Local Ports", uses_ports ? details::PortConditionToString(fw_rule->LocalPorts) : not_applicable);
	append_line(L"Remote Ports", uses_ports ? details::PortConditionToString(fw_rule->RemotePorts) : not_applicable);

	const auto any_icmp_type_code = details::NotRestrictedText(L"any ICMP type and code");
	std::wstring icmp_type_codes = not_applicable;
	if (protocol == IPPROTO_ICMP)
	{
		icmp_type_codes = details::IcmpTypeCodesToString(fw_rule->V4TypeCodeList, any_icmp_type_code.c_str());
	}
	else if (protocol == IPPROTO_ICMPV6)
	{
		icmp_type_codes = details::IcmpTypeCodesToString(fw_rule->V6TypeCodeList, any_icmp_type_code.c_str());
	}
	append_line(L"ICMP Type/Code Constraints", icmp_type_codes);

	return return_string;
}
