// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Verifies that NormalizedFirewallRule::PrintRule prints the same fields for every schema version and IP protocol,
// with placeholders for fields the rule's schema version or protocol cannot carry.

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <string_view>

#include <io.h>
#include <wil/network.h>
#include <Windows.h>
#include <sddl.h>
#include <userenv.h>
#include <wil/resource.h>

#include "..\NormalizedFirewallRule.h"
#include "..\ApplicationAnalysis.h"
#include "..\PackageAnalysis.h"
#include "..\UserOwnerAnalysis.h"
#include "..\FilterRanking.h"
#include "..\DuplicateAnalysis.h"

bool
VerboseOutputEnabled() noexcept
{
	return false;
}

bool
DebugOutputEnabled() noexcept
{
	return false;
}

// the failures DeleteDuplicateRules reports, in order
std::vector<HRESULT> g_recorded_failures;

void
RecordOperationFailure(HRESULT error) noexcept
{
	g_recorded_failures.push_back(error);
}

namespace
{
int g_failures = 0;
int g_checks = 0;

void
Check(bool condition, const char* description)
{
	++g_checks;
	if (!condition)
	{
		++g_failures;
		std::printf("FAIL: %s\n", description);
	}
}

using PrintedFields = std::vector<std::pair<std::wstring, std::wstring>>;

PrintedFields
ParsePrintedRule(const std::wstring& printed)
{
	PrintedFields fields;
	size_t line_start = 0;
	while (line_start < printed.size())
	{
		auto line_end = printed.find(L'\n', line_start);
		if (line_end == std::wstring::npos)
		{
			line_end = printed.size();
		}
		const auto line = printed.substr(line_start, line_end - line_start);
		line_start = line_end + 1;

		// platform validity entries are printed as indented continuation lines
		if (line.starts_with(L"  - "))
		{
			continue;
		}
		const auto separator = line.find(L": ");
		if (separator == std::wstring::npos)
		{
			fields.emplace_back(line, L"");
		}
		else
		{
			fields.emplace_back(line.substr(0, separator), line.substr(separator + 2));
		}
	}
	return fields;
}

std::vector<std::wstring>
Labels(const PrintedFields& fields)
{
	std::vector<std::wstring> labels;
	for (const auto& [label, value] : fields)
	{
		labels.push_back(label);
	}
	return labels;
}

std::wstring
ValueOf(const PrintedFields& fields, std::wstring_view label)
{
	for (const auto& [field_label, value] : fields)
	{
		if (field_label == label)
		{
			return value;
		}
	}
	return L"<missing label>";
}

wchar_t g_rule_id[] = L"{TEST-RULE}";
wchar_t g_package_family_name[] = L"Contoso.App_8wekyb3d8bbwe";
wchar_t g_empty_string[] = L"";

FW_RULE
MakeRule(WORD schema_version, WORD protocol)
{
	FW_RULE rule{};
	rule.wSchemaVersion = schema_version;
	rule.wszRuleId = g_rule_id;
	rule.Direction = FW_DIR_IN;
	rule.Action = FW_RULE_ACTION_ALLOW;
	rule.wIpProtocol = protocol;
	// values a rule with an older schema version cannot carry; they must never be printed for such rules
	rule.providerContextKey = {0x11111111, 0x2222, 0x3333, {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}};
	rule.wszPackageFamilyName = g_package_family_name;
	return rule;
}

PrintedFields
Print(const FW_RULE& rule, WORD requested_version)
{
	const NormalizedFirewallRule normalized_rule{&rule, requested_version};
	return ParsePrintedRule(normalized_rule.PrintRule());
}

void
TestSameLabelsForEverySchemaVersionAndProtocol()
{
	const auto expected_labels = Labels(Print(MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP), FW_BINARY_VERSION_33));
	Check(expected_labels.size() > 50, "PrintRule prints every FW_RULE field");

	const std::pair<WORD, WORD> versions[]{
	    {FW_BINARY_VERSION_27, FW_BINARY_VERSION_27},
	    {FW_BINARY_VERSION_31, FW_BINARY_VERSION_27},
	    {FW_BINARY_VERSION_31, FW_BINARY_VERSION_31},
	    {FW_BINARY_VERSION_33, FW_BINARY_VERSION_27},
	    {FW_BINARY_VERSION_33, FW_BINARY_VERSION_31},
	    {FW_BINARY_VERSION_31, FW_BINARY_VERSION_33},
	    {FW_BINARY_VERSION_33, FW_BINARY_VERSION_33}};
	constexpr WORD protocols[]{IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6, FW_IP_PROTOCOL_ANY, 47};
	for (const auto& [requested_version, schema_version] : versions)
	{
		for (const auto protocol : protocols)
		{
			Check(
			    Labels(Print(MakeRule(schema_version, protocol), requested_version)) == expected_labels,
			    "the same labels print in the same order for every schema version and protocol");
		}
	}
}

void
TestPlaceholdersForFieldsTheSchemaVersionCannotCarry()
{
	const auto rule_227 = Print(MakeRule(FW_BINARY_VERSION_27, IPPROTO_TCP), FW_BINARY_VERSION_33);
	Check(
	    ValueOf(rule_227, L"Provider Context Key") == L"(not available in schema version 2.27)",
	    "2.31 field is a placeholder for a 2.27 rule");
	Check(
	    ValueOf(rule_227, L"Remote Dynamic Keyword Address IDs") == L"(not available in schema version 2.27)",
	    "2.31 list field is a placeholder for a 2.27 rule");
	Check(
	    ValueOf(rule_227, L"Package Family Name") == L"(not available in schema version 2.27)",
	    "2.33 field is a placeholder for a 2.27 rule");

	// a store opened at 2.31 allocates 2.31-sized rules, even when the rule itself is newer
	const auto rule_opened_at_231 = Print(MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP), FW_BINARY_VERSION_31);
	Check(
	    ValueOf(rule_opened_at_231, L"Package Family Name") == L"(not available in schema version 2.31)",
	    "2.33 field is a placeholder when the store was opened at 2.31");
	Check(
	    ValueOf(rule_opened_at_231, L"Provider Context Key") == L"{11111111-2222-3333-4444-444444444444}",
	    "2.31 field prints when both versions support it");

	const auto rule_233 = Print(MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP), FW_BINARY_VERSION_33);
	Check(ValueOf(rule_233, L"Package Family Name") == g_package_family_name, "2.33 field prints for a 2.33 rule");
	Check(
	    ValueOf(rule_233, L"Remote Dynamic Keyword Address IDs") == L"(not restricted by dynamic keyword addresses)",
	    "empty supported dynamic keyword list prints the effective policy");
}

void
TestPackageFamilyNameAccessor()
{
	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	Check(
	    NormalizedFirewallRule(&rule, FW_BINARY_VERSION_33).PackageFamilyName() == g_package_family_name,
	    "PackageFamilyName returns the field when both versions support it");
	Check(
	    NormalizedFirewallRule(&rule, FW_BINARY_VERSION_31).PackageFamilyName() == nullptr,
	    "PackageFamilyName is nullptr when the requested version predates it");

	rule.wSchemaVersion = FW_BINARY_VERSION_31;
	Check(
	    NormalizedFirewallRule(&rule, FW_BINARY_VERSION_33).PackageFamilyName() == nullptr,
	    "PackageFamilyName is nullptr when the rule's schema version predates it");
}

void
TestEmptyAndNullText()
{
	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	rule.wszPackageFamilyName = nullptr;
	rule.wszDescription = g_empty_string;
	rule.wszGPOName = nullptr;
	const auto printed = Print(rule, FW_BINARY_VERSION_33);
	Check(
	    ValueOf(printed, L"Package Family Name") == L"(not restricted - any package family)",
	    "null condition text prints the effective policy");
	Check(ValueOf(printed, L"Description") == L"(empty)", "empty informational text prints (empty)");
	Check(ValueOf(printed, L"GPO Name") == L"(none)", "null informational text prints (none)");
	Check(
	    ValueOf(printed, L"Local Application") == L"(not restricted - any application)",
	    "absent application prints the effective policy");
}

PrintedFields
PrintContents(const FW_RULE& rule, WORD requested_version);

void
TestEmptyConditionsPrintTheEffectivePolicy()
{
	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	rule.dwProfiles = FW_PROFILE_TYPE_ALL;
	const auto printed = Print(rule, FW_BINARY_VERSION_33);
	Check(ValueOf(printed, L"Profiles") == L"0x7fffffff (not restricted - all profiles)", "all profiles");
	Check(ValueOf(printed, L"Local Ports") == L"(not restricted - any port)", "no ports or keywords is any port");
	Check(
	    ValueOf(printed, L"Local Address V4 Subnets") == L"(not restricted - any address)",
	    "no addresses or keywords is any address");
	Check(
	    ValueOf(printed, L"Local Interface IDs") == L"(not restricted - all interfaces)",
	    "no interface IDs is all interfaces");
	Check(
	    ValueOf(printed, L"Local Interface Types") == L"0x0 (not restricted - all interface types)",
	    "interface types 0 is all interface types");
	Check(ValueOf(printed, L"Network Names") == L"(not restricted - any network)", "no network names");
	Check(ValueOf(printed, L"Platform Validity List") == L"(not restricted - all platforms)", "no platforms");

	// keywords restrict a condition even when its list is empty
	auto keyword_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	keyword_rule.LocalPorts.wPortKeywords = FW_PORT_KEYWORD_DYNAMIC_RPC_PORTS;
	keyword_rule.RemoteAddresses.dwV6AddressKeywords = FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
	const auto keywords = Print(keyword_rule, FW_BINARY_VERSION_33);
	Check(
	    ValueOf(keywords, L"Local Ports") == L"(set by port keywords: DynamicRpcPorts)",
	    "port keywords are the restriction when the port list is empty");
	Check(
	    ValueOf(keywords, L"Remote Address V4 Subnets") == L"(set by address keywords: LocalSubnet)",
	    "address keywords are the restriction when the address lists are empty");
	const auto keyword_contents = PrintContents(keyword_rule, FW_BINARY_VERSION_33);
	Check(
	    ValueOf(keyword_contents, L"Local Ports") == L"(set by port keywords: DynamicRpcPorts)",
	    "PrintRuleContents port keywords restriction");
	Check(
	    ValueOf(keyword_contents, L"Local Addresses Constraints") == L"(not restricted - any address)",
	    "PrintRuleContents any local address");
	Check(
	    ValueOf(keyword_contents, L"Remote Addresses Constraints") == L"IPv4 (None) IPv6 (LocalSubnet)",
	    "PrintRuleContents remote address keywords");

	// one address list restricts the side, so the other empty lists are just empty
	FW_IPV4_SUBNET subnets[]{{0x0a000000, 0xff000000}};
	auto subnet_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	subnet_rule.LocalAddresses.V4SubNets = {1, subnets};
	const auto subnet = Print(subnet_rule, FW_BINARY_VERSION_33);
	Check(ValueOf(subnet, L"Local Address V4 Subnets") == L"1 entries", "address list count prints");
	Check(ValueOf(subnet, L"Local Address V6 Ranges") == L"(none)", "other address lists are empty, not any address");

	// dynamic keyword addresses restrict the remote address when there are no remote address lists or keywords
	GUID dynamic_keyword_ids[]{{0x55555555, 0x6666, 0x7777, {0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}}};
	auto dynamic_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	dynamic_rule.RemoteDynamicKeywordAddresses = {1, dynamic_keyword_ids};
	Check(
	    ValueOf(Print(dynamic_rule, FW_BINARY_VERSION_33), L"Remote Address V4 Subnets") ==
	        L"(set by dynamic keyword addresses)",
	    "dynamic keyword addresses restrict the remote address");

	auto any_protocol_rule = MakeRule(FW_BINARY_VERSION_33, FW_IP_PROTOCOL_ANY);
	Check(
	    ValueOf(PrintContents(any_protocol_rule, FW_BINARY_VERSION_33), L"Protocol") ==
	        L"(not restricted - any protocol)",
	    "any protocol prints the effective policy");

	auto icmp_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_ICMP);
	Check(
	    ValueOf(Print(icmp_rule, FW_BINARY_VERSION_33), L"ICMP v4 Type/Code List") ==
	        L"(not restricted - any ICMP type and code)",
	    "no ICMP type/codes is any type and code");
}

void
TestPortsAndIcmpFollowTheProtocol()
{
	FW_PORT_RANGE local_ports[]{{80, 80}, {443, 445}};
	auto tcp_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	tcp_rule.LocalPorts.Ports = {2, local_ports};
	const auto tcp = Print(tcp_rule, FW_BINARY_VERSION_33);
	Check(ValueOf(tcp, L"Local Ports") == L"80, 443-445", "TCP local ports print");
	Check(ValueOf(tcp, L"Remote Ports") == L"(not restricted - any port)", "TCP rule without remote ports is any port");
	Check(
	    ValueOf(tcp, L"ICMP v4 Type/Code List") == L"(not applicable to IP protocol 6)",
	    "ICMP list is not read for a TCP rule");

	// ports and ICMP type/codes share a union, so an ICMP rule must not print its type/codes as ports
	FW_ICMP_TYPE_CODE type_codes[]{{8, 0}};
	auto icmp_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_ICMP);
	icmp_rule.V4TypeCodeList = {1, type_codes};
	const auto icmp = Print(icmp_rule, FW_BINARY_VERSION_33);
	Check(ValueOf(icmp, L"ICMP v4 Type/Code List") == L"[type] 8 - [code] 0", "ICMPv4 type/codes print");
	Check(
	    ValueOf(icmp, L"ICMP v6 Type/Code List") == L"(not applicable to IP protocol 1)",
	    "ICMPv6 list is not read for an ICMPv4 rule");
	Check(ValueOf(icmp, L"Local Ports") == L"(not applicable to IP protocol 1)", "ports are not read for an ICMP rule");

	auto icmpv6_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_ICMPV6);
	icmpv6_rule.V6TypeCodeList = {1, type_codes};
	const auto icmpv6 = Print(icmpv6_rule, FW_BINARY_VERSION_33);
	Check(ValueOf(icmpv6, L"ICMP v6 Type/Code List") == L"[type] 8 - [code] 0", "ICMPv6 type/codes print");
	Check(
	    ValueOf(icmpv6, L"ICMP v4 Type/Code List") == L"(not applicable to IP protocol 58)",
	    "ICMPv4 list is not read for an ICMPv6 rule");
}

void
TestHexValues()
{
	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	rule.dwProfiles = 0x10;
	rule.Status = static_cast<FW_RULE_STATUS>(0x20000);
	const auto printed = Print(rule, FW_BINARY_VERSION_33);
	Check(ValueOf(printed, L"Profiles") == L"0x10", "0x-prefixed values are hexadecimal");
	Check(ValueOf(printed, L"Status") == L"0x00020000", "non-OK status prints as 8-digit hexadecimal, matching JSON");
}

PrintedFields
PrintContents(const FW_RULE& rule, WORD requested_version)
{
	const NormalizedFirewallRule normalized_rule{&rule, requested_version};
	const auto printed = PrintRuleContents(normalized_rule, 1);

	// drop the numbered "Rule Name" heading and the indentation, leaving "Label: value" lines
	std::wstring fields;
	size_t line_start = 0;
	while (line_start < printed.size())
	{
		auto line_end = printed.find(L'\n', line_start);
		if (line_end == std::wstring::npos)
		{
			line_end = printed.size();
		}
		const auto line = printed.substr(line_start, line_end - line_start);
		line_start = line_end + 1;
		if (line.find(L" : Rule Name: ") == std::wstring::npos)
		{
			fields += line.substr(line.find_first_not_of(L' ')) + L"\n";
		}
	}
	return ParsePrintedRule(fields);
}

wchar_t g_local_service[] = L"TestService";
wchar_t g_local_application[] = L"%SystemRoot%\\system32\\svchost.exe";
wchar_t g_package_id[] = L"S-1-15-2-1";
wchar_t g_local_user_authorization_list[] = L"O:LSD:(A;;CC;;;S-1-5-18)";
wchar_t g_system_sid[] = L"S-1-5-18";
wchar_t g_unknown_sid[] = L"S-1-5-21-1-2-3-999999";
GUID g_dynamic_keyword_ids[]{{0x55555555, 0x6666, 0x7777, {0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}}};
FW_PORT_RANGE g_remote_ports[]{{1024, 2048}};

std::wstring
NotAvailablePlaceholder(WORD schema_version)
{
	return std::format(L"(not available in schema version {}.{})", HIBYTE(schema_version), LOBYTE(schema_version));
}

// a rule using most fields, so values common to every schema version can be compared across versions
FW_RULE
MakePopulatedRule(WORD schema_version, WORD protocol)
{
	auto rule = MakeRule(schema_version, protocol);
	rule.wszDescription = g_rule_id;
	rule.dwProfiles = 0x5;
	rule.wFlags = FW_RULE_FLAGS_ACTIVE;
	rule.wszLocalService = g_local_service;
	rule.wszLocalApplication = g_local_application;
	rule.wszPackageId = g_package_id;
	rule.wszLocalUserAuthorizationList = g_local_user_authorization_list;
	rule.LocalAddresses.dwV4AddressKeywords = FW_ADDRESS_KEYWORD_LOCAL_SUBNET;
	rule.RemoteAddresses.dwV6AddressKeywords = FW_ADDRESS_KEYWORD_DNS | FW_ADDRESS_KEYWORD_DHCP;
	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
	{
		rule.LocalPorts.wPortKeywords = FW_PORT_KEYWORD_DYNAMIC_RPC_PORTS;
		rule.RemotePorts.Ports = {1, g_remote_ports};
	}
	rule.RemoteDynamicKeywordAddresses = {1, g_dynamic_keyword_ids};
	return rule;
}

void
TestPopulatedRulesPrintTheSameAcrossSchemaVersions()
{
	constexpr WORD versions[]{FW_BINARY_VERSION_27, FW_BINARY_VERSION_31, FW_BINARY_VERSION_33};
	constexpr WORD protocols[]{IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6, FW_IP_PROTOCOL_ANY};
	// fields that only some schema versions carry; every other field must print the same value for every version
	const std::wstring_view version_specific_labels[]{
	    L"Schema Version",
	    L"Provider Context Key",
	    L"Remote Dynamic Keyword Address IDs",
	    L"Package Family Name"};
	const auto is_version_specific = [&](const std::wstring& label)
	{
		return std::ranges::find(version_specific_labels, label) != std::end(version_specific_labels);
	};

	for (const auto protocol : protocols)
	{
		const auto newest_rule = MakePopulatedRule(FW_BINARY_VERSION_33, protocol);
		const auto newest = Print(newest_rule, FW_BINARY_VERSION_33);
		const auto newest_contents = PrintContents(newest_rule, FW_BINARY_VERSION_33);
		for (const auto version : versions)
		{
			const auto rule = MakePopulatedRule(version, protocol);
			const auto printed = Print(rule, FW_BINARY_VERSION_33);
			const auto contents = PrintContents(rule, FW_BINARY_VERSION_33);
			Check(Labels(printed) == Labels(newest), "PrintRule labels match the newest schema version");
			Check(
			    Labels(contents) == Labels(newest_contents),
			    "PrintRuleContents labels match the newest schema version");
			for (size_t index = 0; index < printed.size() && index < newest.size(); ++index)
			{
				if (!is_version_specific(printed[index].first))
				{
					Check(
					    printed[index].second == newest[index].second,
					    "PrintRule values common to every schema version match");
				}
			}
			for (size_t index = 0; index < contents.size() && index < newest_contents.size(); ++index)
			{
				if (!is_version_specific(contents[index].first))
				{
					Check(
					    contents[index].second == newest_contents[index].second,
					    "PrintRuleContents values common to every schema version match");
				}
			}

			const auto expected_pfn = version >= FW_BINARY_VERSION_33 ? std::wstring{g_package_family_name}
			                                                          : NotAvailablePlaceholder(version);
			Check(ValueOf(printed, L"Package Family Name") == expected_pfn, "PrintRule package family name");
			Check(ValueOf(contents, L"Package Family Name") == expected_pfn, "PrintRuleContents package family name");
			Check(
			    ValueOf(printed, L"Remote Dynamic Keyword Address IDs") ==
			        (version >= FW_BINARY_VERSION_31 ? std::wstring{L"{55555555-6666-7777-8888-888888888888}"}
			                                         : NotAvailablePlaceholder(version)),
			    "PrintRule dynamic keywords");
		}
	}
}

void
TestPrintRuleContentsValues()
{
	const auto tcp = PrintContents(MakePopulatedRule(FW_BINARY_VERSION_33, IPPROTO_TCP), FW_BINARY_VERSION_33);
	Check(ValueOf(tcp, L"Description") == g_rule_id, "description prints");
	Check(ValueOf(tcp, L"Local Service") == g_local_service, "local service prints");
	Check(ValueOf(tcp, L"Application") == g_local_application, "application prints");
	Check(ValueOf(tcp, L"Package ID") == g_package_id, "package ID prints");
	Check(ValueOf(tcp, L"User") == L"(not restricted - all users)", "rule without an owner applies to all users");
	Check(
	    ValueOf(tcp, L"Local User Authorization List") == g_local_user_authorization_list,
	    "local user authorization list prints");
	Check(ValueOf(tcp, L"Local Addresses Constraints") == L"IPv4 (LocalSubnet) IPv6 (None)", "local keywords print");
	Check(ValueOf(tcp, L"Remote Addresses Constraints") == L"IPv4 (None) IPv6 (DNS DHCP)", "remote keywords print");
	Check(
	    ValueOf(tcp, L"Target Address Constraints") == L"(not restricted by address subnets or ranges)",
	    "no address lists print the effective policy");
	Check(ValueOf(tcp, L"Protocol") == L"TCP", "protocol prints");
	Check(ValueOf(tcp, L"Local Port Constraints") == L"DynamicRpcPorts", "port keyword prints");
	Check(ValueOf(tcp, L"Remote Port Constraints") == L"None", "no port keyword prints None");
	Check(
	    ValueOf(tcp, L"Local Ports") == L"(set by port keywords: DynamicRpcPorts)",
	    "no local ports with a keyword prints the keyword restriction");
	Check(ValueOf(tcp, L"Remote Ports") == L"1024-2048", "remote port range prints");
	Check(ValueOf(tcp, L"ICMP Type/Code Constraints") == L"(not applicable to TCP)", "ICMP is not read for TCP");

	FW_ICMP_TYPE_CODE type_codes[]{{8, 256}};
	auto icmp_rule = MakeRule(FW_BINARY_VERSION_27, IPPROTO_ICMP);
	icmp_rule.V4TypeCodeList = {1, type_codes};
	const auto icmp = PrintContents(icmp_rule, FW_BINARY_VERSION_33);
	Check(ValueOf(icmp, L"ICMP Type/Code Constraints") == L"[type] 8 - [code] 256", "ICMPv4 type/code prints");
	Check(ValueOf(icmp, L"Local Ports") == L"(not applicable to ICMPv4)", "ports are not read for ICMP");

	auto unknown_owner = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	unknown_owner.wszLocalUserOwner = g_unknown_sid;
	Check(
	    ValueOf(PrintContents(unknown_owner, FW_BINARY_VERSION_33), L"User") ==
	        std::wstring{g_unknown_sid} + L" (not resolved)",
	    "an unresolved owner prints its SID");
}

void
TestResolvedUserNameHasNoEmbeddedNull()
{
	// LookupAccountSid sizes include the terminator on the first call; a name that keeps it truncates the printout
	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	rule.wszLocalUserOwner = g_system_sid;
	const NormalizedFirewallRule normalized_rule{&rule, FW_BINARY_VERSION_33};
	Check(normalized_rule.successfully_resolved_user_name.value_or(false), "the SYSTEM SID resolves");
	Check(
	    !normalized_rule.local_user_owner_name.empty() &&
	        normalized_rule.local_user_owner_name.find(L'\0') == std::wstring::npos,
	    "the resolved user name has no embedded null");
	Check(
	    !normalized_rule.local_user_domain_name.empty() &&
	        normalized_rule.local_user_domain_name.find(L'\0') == std::wstring::npos,
	    "the resolved domain name has no embedded null");

	const auto contents = PrintContents(rule, FW_BINARY_VERSION_33);
	Check(
	    ValueOf(contents, L"User") ==
	        normalized_rule.local_user_domain_name + L"\\" + normalized_rule.local_user_owner_name,
	    "the resolved user prints as domain\\name");
	Check(Labels(contents).back() == L"ICMP Type/Code Constraints", "fields after the user still print");
}

wchar_t g_app_rule_ids[6][16]{
    L"{APP-RULE-0}", L"{APP-RULE-1}", L"{APP-RULE-2}", L"{APP-RULE-3}", L"{APP-RULE-4}", L"{APP-RULE-5}"};
wchar_t g_system_application[] = L"System";
wchar_t g_existing_application[] = L"%SystemRoot%\\System32\\svchost.exe";
wchar_t g_per_user_application[] = L"%HOMEPATH%\\app.exe";
wchar_t g_missing_application[] = L"C:\\FwDiagnoseTest-missing\\app.exe";
wchar_t g_service_profile_application[] = L"%APPDATA%\\app.exe";
wchar_t g_per_user_rule_name[] = L"Per-user rule";
wchar_t g_service_rule_name[] = L"Service rule";

constexpr PCWSTR ApplicationSummaryHeader = L"  * Summary of application analysis of firewall rules:\n";
constexpr PCWSTR PerUserCountLine =
    L"     - of those, using a per-user environment variable (the Firewall service resolves it as LocalService): ";
constexpr PCWSTR ServiceProfileCountLine =
    L"   - WARNING: count of rules with an application exe using %USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%, "
    L"or %TMP% (resolves within the profile of the Firewall service account): ";
constexpr PCWSTR Wow64SkipLine =
    L"  * Skipping the check for missing application files: this 32-bit build cannot see the same paths as the "
    L"Firewall on 64-bit Windows - use the 64-bit build\n";

void
TestApplicationAnalysisWithNoApplicationRules()
{
	const auto empty = AnalyzeApplicationRules({}, ApplicationFileCheck::Completed);
	Check(empty.applicationRuleCount == 0 && empty.perUserVariableRuleCount == 0, "no rules have no counts");
	Check(
	    empty.missingApplicationRules.empty() && empty.serviceProfileVariableRules.empty(),
	    "no rules have no findings");
	Check(
	    PrintApplicationAnalysis(empty, AnalysisOutput::Summary).empty(),
	    "the summary prints nothing when there is nothing to report");
	Check(
	    PrintApplicationAnalysis(empty, AnalysisOutput::Verbose) ==
	        std::wstring{ApplicationSummaryHeader} + L"   - count of rules with an application exe: 0\n" +
	            L"   - count of rules with an application exe referencing non-existing file: 0\n" + PerUserCountLine +
	            L"0\n",
	    "verbose output prints zero counts and no lists");

	// a rule without an application is not an application rule
	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	std::vector<NormalizedFirewallRule> rules;
	rules.emplace_back(&rule, FW_BINARY_VERSION_33);
	Check(
	    AnalyzeApplicationRules(rules, ApplicationFileCheck::Completed).applicationRuleCount == 0,
	    "a rule without an application is not counted");

	Check(
	    PrintApplicationAnalysis(
	        AnalyzeApplicationRules({}, ApplicationFileCheck::SkippedWow64Redirection),
	        AnalysisOutput::Summary) == Wow64SkipLine,
	    "the WOW64 skip is printed even when there is nothing else to report");
}

void
TestApplicationAnalysisWithEveryKindOfApplicationRule()
{
	FW_RULE fw_rules[6]{};
	for (size_t index = 0; index < std::size(fw_rules); ++index)
	{
		fw_rules[index] = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rules[index].wszRuleId = g_app_rule_ids[index];
	}
	// fw_rules[0] has no application
	fw_rules[1].wszLocalApplication = g_system_application;
	fw_rules[2].wszLocalApplication = g_existing_application;
	fw_rules[3].wszLocalApplication = g_per_user_application;
	fw_rules[3].wszName = g_per_user_rule_name;
	fw_rules[4].wszLocalApplication = g_missing_application;
	fw_rules[5].wszLocalApplication = g_service_profile_application;
	fw_rules[5].wszName = g_service_rule_name;

	std::vector<NormalizedFirewallRule> rules;
	for (const auto& fw_rule : fw_rules)
	{
		rules.emplace_back(&fw_rule, FW_BINARY_VERSION_33);
	}

	if (RunningUnderWow64())
	{
		std::printf("SKIP: file lookups are not performed by a 32-bit build on 64-bit Windows\n");
		return;
	}

	const auto analysis = AnalyzeApplicationRules(rules, ApplicationFileCheck::Completed);
	Check(analysis.applicationRuleCount == 5, "every rule with an application is counted, including System");
	Check(analysis.perUserVariableRuleCount == 1, "the per-user variable rule is counted");
	Check(analysis.missingApplicationRules.size() == 2, "only the per-user and missing files are missing");
	Check(analysis.serviceProfileVariableRules.size() == 1, "the service-profile variable rule is a warning");
	if (analysis.missingApplicationRules.size() == 2 && analysis.serviceProfileVariableRules.size() == 1)
	{
		const auto& per_user = analysis.missingApplicationRules[0];
		Check(
		    per_user.reason == ApplicationFindingReason::PerUserEnvironmentVariable && per_user.error == S_OK,
		    "a per-user variable is reported without a file lookup");
		Check(std::wstring_view{per_user.name} == g_per_user_rule_name, "the finding keeps the rule name");
		const auto& missing = analysis.missingApplicationRules[1];
		Check(
		    missing.reason == ApplicationFindingReason::FileLookupFailed &&
		        missing.error == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND),
		    "a failed lookup keeps its error");
		Check(
		    missing.name == nullptr && std::wstring_view{missing.ruleId} == g_app_rule_ids[4],
		    "a rule without a name keeps its ID");
		Check(
		    std::wstring_view{analysis.serviceProfileVariableRules[0].application} == g_service_profile_application,
		    "the warning keeps the application path");
	}

	// the console prints the normalized (lowercase) rule name, as it always has
	const std::wstring counts = std::wstring{ApplicationSummaryHeader} +
	                            L"   - count of rules with an application exe: 5\n" +
	                            L"   - count of rules with an application exe referencing non-existing file: 2\n" +
	                            PerUserCountLine + L"1\n" + ServiceProfileCountLine + L"1\n" +
	                            L"     WARNING: Application-exe:  '%APPDATA%\\app.exe'  [Rule Name:  service rule]\n";
	Check(
	    PrintApplicationAnalysis(analysis, AnalysisOutput::Summary) == counts,
	    "the summary prints counts and warnings without the missing-file list");
	Check(
	    PrintApplicationAnalysis(analysis, AnalysisOutput::Verbose) ==
	        counts + L"   - rules with an application exe referencing non-existing file:\n" +
	            L"     Application-exe:  '%HOMEPATH%\\app.exe' (per-user environment variable)  (Contains per-user "
	            L"environment variable) [Rule Name:  per-user rule]\n" +
	            L"     Application-exe:  'C:\\FwDiagnoseTest-missing\\app.exe'  (Failed to find the file (0x80070003)) "
	            L"[(no Rule Name) RuleId:  {APP-RULE-4}]\n",
	    "verbose output lists every missing file");
}

void
TestApplicationAnalysisWithNullFindingFields()
{
	ApplicationAnalysis analysis;
	analysis.applicationRuleCount = 1;
	analysis.missingApplicationRules.push_back(
	    {.reason = ApplicationFindingReason::FileLookupFailed,
	     .error = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND),
	     .failureText = "Failed to find the file (0x80070002)"});
	Check(
	    PrintApplicationAnalysis(analysis, AnalysisOutput::Verbose)
	        .ends_with(
	            L"     Application-exe:  '(none)'  (Failed to find the file (0x80070002)) [(no Rule Name) RuleId:  "
	            L"(none)]\n"),
	    "a finding without a rule ID or application prints placeholders");
}

wchar_t g_package_rule_ids[6][16]{
    L"{PKG-RULE-0}", L"{PKG-RULE-1}", L"{PKG-RULE-2}", L"{PKG-RULE-3}", L"{PKG-RULE-4}", L"{PKG-RULE-5}"};
wchar_t g_installed_package_id[] = L"S-1-15-2-1";
wchar_t g_missing_package_id[] = L"S-1-15-2-999";
wchar_t g_missing_package_family_name[] = L"Missing.App_x";
wchar_t g_both_missing_rule_name[] = L"Both Missing";

constexpr PCWSTR PackageSummaryHeader = L"  * Summary of app-package analysis of firewall rules:\n";

std::wstring
PackageCounts(size_t idRules, size_t missingIdRules, size_t familyNameRules, size_t missingFamilyNameRules)
{
	return std::wstring{PackageSummaryHeader} + std::format(L"   - count of rules with a package ID: {}\n", idRules) +
	       std::format(
	           L"   - count of rules with a package ID referencing a non-existing package: {}\n",
	           missingIdRules) +
	       std::format(L"   - count of rules with a package family name: {}\n", familyNameRules) +
	       std::format(
	           L"   - count of rules with a package family name referencing a non-existing package: {}\n",
	           missingFamilyNameRules);
}

PackageLookups
InstalledPackageLookups(size_t& lookupCount)
{
	return {
	    [&lookupCount](PCWSTR package_sid)
	    {
		    ++lookupCount;
		    return std::wstring_view{package_sid} == g_installed_package_id;
	    },
	    [&lookupCount](const NormalizedString& package_family_name)
	    {
		    ++lookupCount;
		    return package_family_name == NormalizedString::Create(std::wstring{g_package_family_name});
	    }};
}

void
TestPackageAnalysisWithNoPackageRules()
{
	size_t lookupCount = 0;
	std::vector<NormalizedFirewallRule> none;
	const auto empty = AnalyzePackageRules(none, S_OK, InstalledPackageLookups(lookupCount), {});
	Check(empty.packageIdRuleCount == 0 && empty.packageFamilyNameRuleCount == 0, "no rules have no package rules");
	Check(
	    PrintPackageAnalysis(empty, AnalysisOutput::Summary) == PackageCounts(0, 0, 0, 0),
	    "the summary always prints its counts, even when they are zero");
	Check(
	    PrintPackageAnalysis(empty, AnalysisOutput::Verbose) == PackageCounts(0, 0, 0, 0),
	    "verbose output prints no list header when nothing is missing");

	auto rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	rule.wszPackageId = g_missing_package_id;
	std::vector<NormalizedFirewallRule> rules;
	rules.emplace_back(&rule, FW_BINARY_VERSION_33);
	const auto failed = AnalyzePackageRules(rules, E_ACCESSDENIED, InstalledPackageLookups(lookupCount), {});
	Check(lookupCount == 0, "no package is looked up when the installed packages could not be loaded");
	Check(
	    failed.packageIdRuleCount == 0 && failed.missingPackageRules.empty() && !rules[0].missing_package_id &&
	        !rules[0].missing_package_family_name,
	    "no rule is counted or flagged when the installed packages could not be loaded");
	Check(
	    PrintPackageAnalysis(failed, AnalysisOutput::Verbose) ==
	        L"  * Skipping the app-package analysis: installed packages could not be loaded (0x80070005)\n",
	    "a load failure prints only the skip line with an 8-digit error code");
}

void
TestPackageAnalysisWithEveryKindOfPackageRule()
{
	FW_RULE fw_rules[6]{};
	for (size_t index = 0; index < std::size(fw_rules); ++index)
	{
		fw_rules[index] = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rules[index].wszRuleId = g_package_rule_ids[index];
	}
	// fw_rules[0] has no package ID and no package family name
	fw_rules[0].wszPackageFamilyName = nullptr;
	// fw_rules[1] references an installed package by both
	fw_rules[1].wszPackageId = g_installed_package_id;
	// fw_rules[2] references a missing package by both
	fw_rules[2].wszPackageId = g_missing_package_id;
	fw_rules[2].wszPackageFamilyName = g_missing_package_family_name;
	fw_rules[2].wszName = g_both_missing_rule_name;
	// fw_rules[3] is a 2.27 rule, which cannot carry a package family name
	fw_rules[3].wSchemaVersion = FW_BINARY_VERSION_27;
	fw_rules[3].wszPackageFamilyName = g_missing_package_family_name;
	// fw_rules[4] references a missing package family name and has no name
	fw_rules[4].wszPackageFamilyName = g_missing_package_family_name;
	// fw_rules[5] has an empty package ID
	fw_rules[5].wszPackageId = g_empty_string;
	fw_rules[5].wszPackageFamilyName = nullptr;

	std::vector<NormalizedFirewallRule> rules;
	for (const auto& fw_rule : fw_rules)
	{
		rules.emplace_back(&fw_rule, FW_BINARY_VERSION_33);
	}

	size_t lookupCount = 0;
	const auto analysis = AnalyzePackageRules(rules, S_OK, InstalledPackageLookups(lookupCount), {});
	Check(analysis.packageIdRuleCount == 2, "only non-empty package IDs are counted");
	Check(analysis.packageFamilyNameRuleCount == 3, "the 2.27 rule's package family name is not counted");
	Check(analysis.MissingCount(PackageReference::PackageId) == 1, "one package ID is missing");
	Check(analysis.MissingCount(PackageReference::PackageFamilyName) == 2, "two package family names are missing");
	Check(lookupCount == 5, "every counted reference is looked up once");
	Check(
	    rules[2].missing_package_id && rules[2].missing_package_family_name && !rules[4].missing_package_id &&
	        rules[4].missing_package_family_name,
	    "missing references are flagged on the rules");
	Check(
	    !rules[0].missing_package_id && !rules[1].missing_package_id && !rules[1].missing_package_family_name &&
	        !rules[3].missing_package_family_name && !rules[5].missing_package_id,
	    "installed, absent, and unreadable references are not flagged");
	if (analysis.missingPackageRules.size() == 3)
	{
		const auto& first = analysis.missingPackageRules[0];
		Check(
		    first.reference == PackageReference::PackageId &&
		        std::wstring_view{first.package} == g_missing_package_id &&
		        std::wstring_view{first.name} == g_both_missing_rule_name,
		    "the finding keeps the package ID and the stored rule name");
		const auto& last = analysis.missingPackageRules[2];
		Check(
		    last.name == nullptr && std::wstring_view{last.ruleId} == g_package_rule_ids[4],
		    "a rule without a name keeps its ID");
	}
	else
	{
		Check(false, "a rule missing both references is reported twice");
	}

	const auto counts = PackageCounts(2, 1, 3, 2);
	Check(
	    PrintPackageAnalysis(analysis, AnalysisOutput::Summary) == counts,
	    "the summary prints counts without the list");
	// the console prints the normalized (lowercase) rule name, as it always has
	Check(
	    PrintPackageAnalysis(analysis, AnalysisOutput::Verbose) ==
	        counts + L"   - rules referencing a non-existing package:\n" +
	            L"     Package-ID:  'S-1-15-2-999'  [Rule Name:  both missing]\n" +
	            L"     Package-Family-Name:  'Missing.App_x'  [Rule Name:  both missing]\n" +
	            L"     Package-Family-Name:  'Missing.App_x'  [(no Rule Name) RuleId:  {PKG-RULE-4}]\n",
	    "verbose output lists missing references in rule order");
}

void
TestPackageAnalysisWithNullFindingFields()
{
	PackageAnalysis analysis;
	analysis.packageIdRuleCount = 1;
	analysis.missingPackageRules.push_back({.reference = PackageReference::PackageId});
	Check(
	    PrintPackageAnalysis(analysis, AnalysisOutput::Verbose)
	        .ends_with(L"     Package-ID:  '(none)'  [(no Rule Name) RuleId:  (none)]\n"),
	    "a finding without a rule ID or package prints placeholders");
}
wchar_t g_user_rule_ids[6][16]{
    L"{USER-RULE-0}", L"{USER-RULE-1}", L"{USER-RULE-2}", L"{USER-RULE-3}", L"{USER-RULE-4}", L"{USER-RULE-5}"};
wchar_t g_invalid_sid[] = L"not-a-sid";
wchar_t g_unmapped_sid[] = L"S-1-5-21-1-2-3-1001";
wchar_t g_no_profile_sid[] = L"S-1-5-21-1-2-3-1002";
wchar_t g_no_profile_no_domain_sid[] = L"S-1-5-21-1-2-3-1003";
wchar_t g_invalid_sid_rule_name[] = L"Bad SID rule";
wchar_t g_no_profile_rule_name[] = L"No profile rule";

constexpr PCWSTR UserOwnerSummaryHeader = L"  * Summary of SID owner analysis of firewall rules:\n";
constexpr PCWSTR UserOwnerSkipLine =
    L"  * Skipping the local-profile check: local profiles could not be read (0x80070005)\n";

std::wstring
UserOwnerCounts(size_t ownerRules, size_t unresolvedRules)
{
	return std::wstring{UserOwnerSummaryHeader} +
	       std::format(L"   - count of rules with LocalUserOwner SID: {}\n", ownerRules) +
	       std::format(
	           L"   - count of rules with LocalUserOwner SID referencing unresolved SID: {}\n",
	           unresolvedRules);
}

std::wstring
MissingProfileCount(size_t missingRules)
{
	return std::format(
	    L"   - count of rules with LocalUserOwner SID referencing non-existing local profile: {}\n",
	    missingRules);
}

void
TestUserOwnerAnalysisWithNoOwnerRules()
{
	auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	std::vector<NormalizedFirewallRule> rules;
	rules.emplace_back(&fw_rule, FW_BINARY_VERSION_33);

	const auto notApplicable = AnalyzeUserOwnerRules(rules, {});
	Check(
	    notApplicable.localUserOwnerRuleCount == 0 && notApplicable.unresolvedSidRules.empty() &&
	        notApplicable.missingLocalProfileRules.empty(),
	    "a rule without an owner is not counted");
	Check(PrintUserOwnerAnalysis(notApplicable, AnalysisOutput::Summary).empty(), "the summary prints nothing");
	Check(
	    PrintUserOwnerAnalysis(notApplicable, AnalysisOutput::Verbose) == UserOwnerCounts(0, 0),
	    "verbose output prints zero counts without the local-profile count when the check does not apply");

	const auto completed = AnalyzeUserOwnerRules(rules, {.check = LocalProfileCheck::Completed});
	Check(
	    PrintUserOwnerAnalysis(completed, AnalysisOutput::Verbose) == UserOwnerCounts(0, 0) + MissingProfileCount(0),
	    "verbose output prints the local-profile count when the check completed");
	Check(
	    !rules[0].successfully_resolved_user_name_with_local_profile.has_value() && !rules[0].unresolve_user_sid,
	    "a rule without an owner is not flagged");

	const auto failed =
	    AnalyzeUserOwnerRules(rules, {.check = LocalProfileCheck::Failed, .readResult = E_ACCESSDENIED});
	Check(
	    PrintUserOwnerAnalysis(failed, AnalysisOutput::Summary) == UserOwnerSkipLine,
	    "the summary prints only the skip line when the profiles could not be read");
	Check(
	    PrintUserOwnerAnalysis(failed, AnalysisOutput::Verbose) == UserOwnerSkipLine + UserOwnerCounts(0, 0),
	    "verbose output prints the skip line and counts without the local-profile count");
}

void
TestUserOwnerAnalysisWithEveryKindOfOwnerRule()
{
	FW_RULE fw_rules[6]{};
	for (size_t index = 0; index < std::size(fw_rules); ++index)
	{
		fw_rules[index] = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rules[index].wszRuleId = g_user_rule_ids[index];
	}
	// fw_rules[0] has no owner; fw_rules[1] has an owner that is not a SID string
	fw_rules[1].wszLocalUserOwner = g_invalid_sid;
	fw_rules[1].wszName = g_invalid_sid_rule_name;
	fw_rules[4].wszName = g_no_profile_rule_name;

	std::vector<NormalizedFirewallRule> rules;
	for (const auto& fw_rule : fw_rules)
	{
		rules.emplace_back(&fw_rule, FW_BINARY_VERSION_33);
	}
	Check(
	    rules[1].resolve_name_failure == UserOwnerResolveFailure::InvalidSidString &&
	        rules[1].resolve_name_error == HRESULT_FROM_WIN32(ERROR_INVALID_SID),
	    "an owner that is not a SID string records why it was not resolved");

	// the remaining owners are set after normalization so the test does not depend on account lookups
	const auto setOwner = [&](size_t index, PWSTR sid, bool resolved, PCWSTR domain, PCWSTR user)
	{
		fw_rules[index].wszLocalUserOwner = sid;
		rules[index].successfully_resolved_user_name = resolved;
		rules[index].local_user_domain_name = domain;
		rules[index].local_user_owner_name = user;
	};
	// fw_rules[2] has a SID with no account, and no name
	setOwner(2, g_unmapped_sid, false, L"", L"");
	rules[2].resolve_name_failure = UserOwnerResolveFailure::AccountLookupFailed;
	rules[2].resolve_name_error = HRESULT_FROM_WIN32(ERROR_NONE_MAPPED);
	rules[2].resolve_name_failure_string = "Failed to lookup account SID (0x80070534)";
	// fw_rules[3] has a local profile; fw_rules[4] and fw_rules[5] do not
	setOwner(3, g_system_sid, true, L"NT AUTHORITY", L"SYSTEM");
	setOwner(4, g_no_profile_sid, true, L"CONTOSO", L"alice");
	setOwner(5, g_no_profile_no_domain_sid, true, L"", L"bob");

	// profile SIDs compare case-insensitively
	const LocalProfiles profiles{.check = LocalProfileCheck::Completed, .sids = {L"s-1-5-18"}};
	const auto analysis = AnalyzeUserOwnerRules(rules, profiles);
	Check(analysis.localUserOwnerRuleCount == 5, "every rule with an owner is counted");
	Check(
	    rules[1].unresolve_user_sid && rules[2].unresolve_user_sid && !rules[3].unresolve_user_sid,
	    "unresolved owners are flagged on the rules");
	Check(
	    rules[3].successfully_resolved_user_name_with_local_profile == true &&
	        rules[4].successfully_resolved_user_name_with_local_profile == false &&
	        rules[5].successfully_resolved_user_name_with_local_profile == false &&
	        !rules[1].successfully_resolved_user_name_with_local_profile.has_value(),
	    "resolved owners are flagged with whether they have a local profile");
	if (analysis.unresolvedSidRules.size() == 2 && analysis.missingLocalProfileRules.size() == 2)
	{
		const auto& invalid = analysis.unresolvedSidRules[0];
		Check(
		    std::wstring_view{invalid.name} == g_invalid_sid_rule_name &&
		        invalid.reason == UserOwnerResolveFailure::InvalidSidString,
		    "the finding keeps the stored rule name and the reason");
		const auto& lookup = analysis.unresolvedSidRules[1];
		Check(
		    lookup.name == nullptr && lookup.reason == UserOwnerResolveFailure::AccountLookupFailed &&
		        lookup.error == HRESULT_FROM_WIN32(ERROR_NONE_MAPPED),
		    "a failed lookup keeps its error");
		const auto& missing = analysis.missingLocalProfileRules[0];
		Check(
		    std::wstring_view{missing.localUserOwnerSid} == g_no_profile_sid &&
		        std::wstring_view{missing.domain} == L"CONTOSO" && std::wstring_view{missing.user} == L"alice",
		    "the finding keeps the SID and account");
	}
	else
	{
		Check(false, "two unresolved owners and two owners without a local profile are reported");
	}

	const auto counts = UserOwnerCounts(5, 2) + MissingProfileCount(2);
	Check(
	    PrintUserOwnerAnalysis(analysis, AnalysisOutput::Summary) == counts,
	    "the summary prints counts without the lists");
	Check(
	    PrintUserOwnerAnalysis(analysis, AnalysisOutput::Verbose) ==
	        counts + L"   - rules with unresolved SIDs:\n" +
	            L"     Unresolved SID:  'not-a-sid'  (Failed to convert string SID to SID (0x80070539))  "
	            L"[Rule Name:  bad sid rule]\n" +
	            L"     Unresolved SID:  'S-1-5-21-1-2-3-1001'  (Failed to lookup account SID (0x80070534))  "
	            L"[(no Rule Name) RuleId:  {USER-RULE-2}]\n" +
	            L"   - rules with no local profile:\n" +
	            L"     SID:  'S-1-5-21-1-2-3-1002' (CONTOSO\\alice)  [Rule Name:  no profile rule]\n" +
	            L"     SID:  'S-1-5-21-1-2-3-1003' (bob)  [(no Rule Name) RuleId:  {USER-RULE-5}]\n",
	    "verbose output lists unresolved owners, then owners without a local profile");

	const auto failed =
	    AnalyzeUserOwnerRules(rules, {.check = LocalProfileCheck::Failed, .readResult = E_ACCESSDENIED});
	Check(
	    failed.unresolvedSidRules.size() == 2 && failed.missingLocalProfileRules.empty(),
	    "unresolved owners are still reported when the profiles could not be read");
	Check(
	    PrintUserOwnerAnalysis(failed, AnalysisOutput::Summary) == UserOwnerSkipLine + UserOwnerCounts(5, 2),
	    "the summary prints the skip line and counts without the local-profile count");
}

void
TestUserOwnerAnalysisWithNullFindingFields()
{
	UserOwnerAnalysis analysis;
	analysis.localProfileCheck = LocalProfileCheck::Completed;
	analysis.unresolvedSidRules.push_back({});
	analysis.missingLocalProfileRules.push_back({});
	const auto printed = PrintUserOwnerAnalysis(analysis, AnalysisOutput::Verbose);
	Check(
	    printed.find(L"     Unresolved SID:  '(none)'  ()  [(no Rule Name) RuleId:  (none)]\n") != std::wstring::npos,
	    "an unresolved finding without a rule ID or SID prints placeholders");
	Check(
	    printed.ends_with(L"     SID:  '(none)' ((empty))  [(no Rule Name) RuleId:  (none)]\n"),
	    "a missing-profile finding without a rule ID, SID, or account prints placeholders");
}
wchar_t g_alpha_name[] = L"Alpha";
wchar_t g_alpha_upper_name[] = L"ALPHA";
wchar_t g_beta_name[] = L"beta";
wchar_t g_gamma_name[] = L"gamma";
wchar_t g_delta_name[] = L"delta";
wchar_t g_epsilon_name[] = L"epsilon";
wchar_t g_alpha_rule_id[] = L"{alpha-1}";
wchar_t g_beta_rule_id[] = L"{beta}";

//
// MakeRankingRules
//
// Returns:
//   Rules named Alpha, beta, ALPHA, gamma, delta, epsilon, in that (unsorted) order. The two
//   Alpha rules share a name but differ in case; the second has no rule ID.
//
std::vector<FW_RULE>
MakeRankingRules()
{
	PWSTR names[]{g_alpha_name, g_beta_name, g_alpha_upper_name, g_gamma_name, g_delta_name, g_epsilon_name};
	std::vector<FW_RULE> fw_rules;
	for (const auto name : names)
	{
		auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rule.wszName = name;
		fw_rules.push_back(fw_rule);
	}
	fw_rules[0].wszRuleId = g_alpha_rule_id;
	fw_rules[1].wszRuleId = g_beta_rule_id;
	fw_rules[2].wszRuleId = nullptr;
	return fw_rules;
}

//
// NormalizeRules
//
// Parameters:
//   fw_rules [in] - the rules to normalize; they must outlive the result, which points into them
//
// Returns:
//   One NormalizedFirewallRule per rule, in the same order.
//
std::vector<NormalizedFirewallRule>
NormalizeRules(const std::vector<FW_RULE>& fw_rules)
{
	std::vector<NormalizedFirewallRule> rules;
	for (const auto& fw_rule : fw_rules)
	{
		rules.emplace_back(&fw_rule, FW_BINARY_VERSION_33);
	}
	return rules;
}

//
// RankedNames
//
// Parameters:
//   ranking [in] - a ranking from AnalyzeFilterRankings
//
// Returns:
//   The ranked rule names in order, each followed by ';', so a test can compare a whole ranking.
//
std::wstring
RankedNames(const std::vector<RankedRuleName>& ranking)
{
	std::wstring names;
	for (const auto& ruleName : ranking)
	{
		names += ruleName.ruleName + L";";
	}
	return names;
}

//
// TestFilterRankingsGroupAndOrderRuleNames
//
// Checks that rule names are grouped case-insensitively, counted once each, ranked by count and
// then by name, limited to 3 (or 10 when verbose), and printed with the expected text.
//
void
TestFilterRankingsGroupAndOrderRuleNames()
{
	const auto fw_rules = MakeRankingRules();
	const auto rules = NormalizeRules(fw_rules);
	size_t calls{};
	const auto counter = [&calls](const NormalizedString& name)
	{
		++calls;
		const std::wstring_view value{name.value};
		if (value == L"alpha")
		{
			return FilterCounts{5, 0};
		}
		if (value == L"beta")
		{
			return FilterCounts{5, 7};
		}
		if (value == L"gamma")
		{
			return FilterCounts{9, 7};
		}
		if (value == L"delta")
		{
			return FilterCounts{1, 7};
		}
		return FilterCounts{0, 3};
	};

	const auto summary = AnalyzeFilterRankings(rules, S_OK, AnalysisOutput::Summary, counter);
	Check(calls == 5, "filters are counted once per rule name, even when rules sharing a name are not adjacent");
	Check(summary.limit == 3, "the summary rankings hold 3 rule names");
	Check(
	    RankedNames(summary.byFilterCount) == L"gamma;alpha;beta;",
	    "rule names are ranked by filter count, then by name; names without filters are not ranked");
	Check(
	    RankedNames(summary.byFilterConditionCount) == L"beta;delta;gamma;",
	    "rule names are ranked by condition count, then by name; names without conditions are not ranked");
	const auto& alpha = summary.byFilterCount[1];
	Check(
	    alpha.ruleCount == 2 && alpha.filterCount == 5 && alpha.filterConditionCount == 0 &&
	        alpha.ruleIds == std::vector<PCWSTR>{g_alpha_rule_id, nullptr},
	    "rule names differing only in case are one entry with every rule ID, including null IDs");
	Check(
	    PrintFilterRankings(summary) == L"\n  * Top 3 rule names by WFP filter count:\n"
	                                    L"    [9 filters] 'gamma'\n"
	                                    L"    [5 filters] 'alpha'  [2 rules match this name]\n"
	                                    L"    [5 filters] 'beta'\n"
	                                    L"\n  * Top 3 rule names by WFP filter-condition count:\n"
	                                    L"    [7 conditions] 'beta'\n"
	                                    L"    [7 conditions] 'delta'\n"
	                                    L"    [7 conditions] 'gamma'\n",
	    "the summary rankings print each rule name once, with the rule count only when it is shared");

	const auto verbose = AnalyzeFilterRankings(rules, S_OK, AnalysisOutput::Verbose, counter);
	Check(
	    verbose.limit == 10 && RankedNames(verbose.byFilterCount) == L"gamma;alpha;beta;delta;" &&
	        RankedNames(verbose.byFilterConditionCount) == L"beta;delta;gamma;epsilon;",
	    "the verbose rankings hold up to 10 rule names");
	Check(
	    PrintFilterRankings(verbose).starts_with(L"\n  * Top 10 rule names by WFP filter count:\n"),
	    "the verbose heading states the verbose limit");
}

//
// TestFilterRankingsWithoutFilters
//
// Checks the rankings when the filters could not be read, when no rule name has filters, and
// when the store has no rules.
//
void
TestFilterRankingsWithoutFilters()
{
	const auto fw_rules = MakeRankingRules();
	const auto rules = NormalizeRules(fw_rules);
	size_t calls{};
	const auto counter = [&calls](const NormalizedString&)
	{
		++calls;
		return FilterCounts{};
	};

	const auto failed = AnalyzeFilterRankings(rules, E_ACCESSDENIED, AnalysisOutput::Summary, counter);
	Check(
	    calls == 0 && failed.byFilterCount.empty() && failed.byFilterConditionCount.empty(),
	    "nothing is ranked when the WFP filters could not be read");
	Check(
	    PrintFilterRankings(failed) ==
	        L"\n  * Skipping the filter rankings: WFP filters could not be read (0x80070005)\n",
	    "a filter-read failure is reported instead of empty rankings");

	const auto noFilters = AnalyzeFilterRankings(rules, S_OK, AnalysisOutput::Verbose, counter);
	Check(
	    noFilters.byFilterCount.empty() && noFilters.byFilterConditionCount.empty() &&
	        PrintFilterRankings(noFilters).empty(),
	    "nothing is printed when no rule name has filters");

	const auto noRules = AnalyzeFilterRankings({}, S_OK, AnalysisOutput::Summary, counter);
	Check(
	    noRules.byFilterCount.empty() && PrintFilterRankings(noRules).empty(),
	    "nothing is printed for a store without rules");
}

wchar_t g_duplicate_rule_ids[9][8]{L"{d1}", L"{d2}", L"{d3}", L"{d4}", L"{d5}", L"{d6}", L"{d7}", L"{d8}", L"{d9}"};
wchar_t g_zz_lower_name[] = L"zz";
wchar_t g_zz_upper_name[] = L"ZZ";
wchar_t g_another_name[] = L"Another";
wchar_t g_long_name[] = L"beta-long-name";
wchar_t g_duplicate_description[] = L"only one rule of the set has this description";
wchar_t g_private_name[] = L"private";
wchar_t g_public_name[] = L"public";
wchar_t g_active_name[] = L"active";

//
// MakeDuplicateRules
//
// Returns:
//   Nine rules: three sets of two duplicate rules and three rules that are not duplicates of anything,
//   in an order that is not sorted by any of the analysis's comparisons:
//     - UDP: "ZZ" {d2} and "zz" {d1}, names differing only in case
//     - blocked: "beta-long-name" {d4} (with a description) and "Another" {d3}, different names
//     - outbound, with an application: two rules with no name, {d6} and {d5}
//     - "private" {d7}, "public" {d8}, and "active" {d9}: "public" differs from "private" only in its
//       profile and from "active" only in the active flag
//
std::vector<FW_RULE>
MakeDuplicateRules()
{
	std::vector<FW_RULE> fw_rules;
	const auto add = [&fw_rules](PWSTR name, PWSTR rule_id)
	{
		auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rule.wszName = name;
		fw_rule.wszRuleId = rule_id;
		fw_rules.push_back(fw_rule);
		return fw_rules.size() - 1;
	};

	for (const auto index :
	     {add(g_zz_upper_name, g_duplicate_rule_ids[1]), add(g_zz_lower_name, g_duplicate_rule_ids[0])})
	{
		fw_rules[index].wIpProtocol = IPPROTO_UDP;
	}
	fw_rules[add(g_private_name, g_duplicate_rule_ids[6])].dwProfiles = FW_PROFILE_TYPE_PRIVATE;
	fw_rules[add(g_public_name, g_duplicate_rule_ids[7])].dwProfiles = FW_PROFILE_TYPE_PUBLIC;
	for (const auto index : {add(g_long_name, g_duplicate_rule_ids[3]), add(g_another_name, g_duplicate_rule_ids[2])})
	{
		fw_rules[index].Action = FW_RULE_ACTION_BLOCK;
	}
	fw_rules[fw_rules.size() - 2].wszDescription = g_duplicate_description;
	for (const auto index : {add(nullptr, g_duplicate_rule_ids[5]), add(nullptr, g_duplicate_rule_ids[4])})
	{
		fw_rules[index].Direction = FW_DIR_OUT;
		fw_rules[index].wszLocalApplication = g_existing_application;
	}
	const auto active = add(g_active_name, g_duplicate_rule_ids[8]);
	fw_rules[active].dwProfiles = FW_PROFILE_TYPE_PUBLIC;
	fw_rules[active].wFlags = FW_RULE_FLAGS_ACTIVE;
	return fw_rules;
}

//
// RuleIdsOf
//
// Parameters:
//   set [in] - a set of duplicate rules from AnalyzeDuplicateRules
//
// Returns:
//   The set's rule IDs in order, each followed by ';', so a test can compare a whole set.
//
std::wstring
RuleIdsOf(const DuplicateRuleSet& set)
{
	std::wstring ids;
	for (auto rule = set.duplicate_rule_begin; rule != set.duplicate_rule_end; ++rule)
	{
		ids += rule->fw_rule->wszRuleId;
		ids += L';';
	}
	return ids;
}

//
// TestDuplicateAnalysisFindsAndOrdersSets
//
// Checks which rules are duplicates (rule ID, name, and description are ignored; profiles and the
// active flag are not), the counts, the alphabetical order of the sets and of the rules within each
// set, and the printed text.
//
void
TestDuplicateAnalysisFindsAndOrdersSets()
{
	const auto fw_rules = MakeDuplicateRules();
	auto rules = NormalizeRules(fw_rules);
	const auto analysis = AnalyzeDuplicateRules(rules);

	Check(
	    analysis.duplicateSets.size() == 3 && analysis.duplicateRuleCount == 6,
	    "rules differing only in rule ID, name, or description are duplicates; profile or active flag differences "
	    "are not");
	if (analysis.duplicateSets.size() != 3)
	{
		return;
	}
	Check(
	    RuleIdsOf(analysis.duplicateSets[0]) == L"{d5};{d6};" &&
	        RuleIdsOf(analysis.duplicateSets[1]) == L"{d3};{d4};" &&
	        RuleIdsOf(analysis.duplicateSets[2]) == L"{d1};{d2};",
	    "sets are ordered alphabetically by the name of their first rule (not shorter names first), and rules "
	    "within a set by name, then rule ID");
	Check(
	    analysis.duplicateSets[0].nameCount == 1 && analysis.duplicateSets[1].nameCount == 2 &&
	        analysis.duplicateSets[2].nameCount == 1,
	    "names differing only in case are the same name");

	const std::wstring summary = L"  * Summary of duplicate analysis of firewall rules:\n"
	                             L"   - count of sets of duplicate rules: 3\n"
	                             L"   - count of rules in sets of duplicate rules: 6\n";
	Check(PrintDuplicateAnalysis(analysis, AnalysisOutput::Summary) == summary, "the summary prints only the counts");
	Check(
	    PrintDuplicateAnalysis(analysis, AnalysisOutput::Verbose) ==
	        summary + L"   - sets of duplicate rules:\n"
	                  L"       [2 rules] (no Rule Name) RuleId:  {d5}  (Application-exe: "
	                  L"'%SystemRoot%\\System32\\svchost.exe')\n"
	                  L"       [2 rules] Rule Name:  another  [2 different names]\n"
	                  L"       [2 rules] Rule Name:  zz\n",
	    "the verbose output lists each set once, by its first rule, with its application and name count");
}

//
// TestDuplicateAnalysisWithoutDuplicates
//
// Checks the output when a store has rules but no duplicates, and when it has no rules.
//
void
TestDuplicateAnalysisWithoutDuplicates()
{
	auto fw_rules = MakeDuplicateRules();
	fw_rules.resize(1);
	auto rules = NormalizeRules(fw_rules);
	const auto analysis = AnalyzeDuplicateRules(rules);
	Check(
	    analysis.duplicateSets.empty() && analysis.duplicateRuleCount == 0,
	    "a single rule is not a set of duplicate rules");
	Check(
	    PrintDuplicateAnalysis(analysis, AnalysisOutput::Summary).empty(),
	    "the summary prints nothing when there are no duplicates");
	Check(
	    PrintDuplicateAnalysis(analysis, AnalysisOutput::Verbose) ==
	        L"  * Summary of duplicate analysis of firewall rules:\n"
	        L"   - count of sets of duplicate rules: 0\n"
	        L"   - count of rules in sets of duplicate rules: 0\n",
	    "the verbose output prints zero counts and no list when there are no duplicates");

	std::vector<NormalizedFirewallRule> none;
	Check(AnalyzeDuplicateRules(none).duplicateSets.empty(), "a store without rules has no duplicates");
}

wchar_t g_keep_ids[4][8]{L"{k1}", L"{k2}", L"{k3}", L"{k4}"};
wchar_t g_keep_upper_alpha[] = L"ALPHA";
wchar_t g_keep_lower_alpha[] = L"alpha";
wchar_t g_keep_zed[] = L"Zed";

//
// TestDuplicateKeepChoices
//
// Checks the names offered when deleting all but one rule of a set: one per different name, in
// alphabetical order, each keeping the first rule with that name, and a rule without a name labeled by
// its rule ID instead of an empty entry.
//
void
TestDuplicateKeepChoices()
{
	std::vector<FW_RULE> fw_rules;
	for (const auto& [name, rule_id] :
	     {std::pair{g_keep_zed, g_keep_ids[0]},
	      std::pair{g_keep_upper_alpha, g_keep_ids[2]},
	      std::pair<PWSTR, PWSTR>{nullptr, g_keep_ids[3]},
	      std::pair{g_keep_lower_alpha, g_keep_ids[1]}})
	{
		auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rule.wszName = name;
		fw_rule.wszRuleId = rule_id;
		fw_rules.push_back(fw_rule);
	}
	auto rules = NormalizeRules(fw_rules);
	const auto analysis = AnalyzeDuplicateRules(rules);
	Check(
	    analysis.duplicateSets.size() == 1 && RuleIdsOf(analysis.duplicateSets[0]) == L"{k4};{k2};{k3};{k1};",
	    "a rule without a name is first in its set");
	if (analysis.duplicateSets.size() != 1)
	{
		return;
	}
	const auto choices = ReturnDuplicateKeepChoices(analysis.duplicateSets[0]);
	Check(
	    choices.size() == 3 && choices[0].label == L"(no Rule Name) RuleId:  {k4}" && choices[0].ruleIndex == 0 &&
	        choices[1].label == L"alpha" && choices[1].ruleIndex == 1 && choices[2].label == L"zed" &&
	        choices[2].ruleIndex == 3,
	    "one choice per name, alphabetically, keeping the first rule with that name; no empty label");

	const auto same_name_rules = MakeDuplicateRules();
	auto same_name = NormalizeRules(same_name_rules);
	const auto same_name_analysis = AnalyzeDuplicateRules(same_name);
	const auto one_choice = ReturnDuplicateKeepChoices(same_name_analysis.duplicateSets.back());
	Check(
	    one_choice.size() == 1 && one_choice[0].label == L"zz" && one_choice[0].ruleIndex == 0,
	    "names differing only in case are one choice");
}

//
// SuppressStdout
//
// Sends stdout to NUL while it exists, so the deletion prompts do not clutter the test output. Check
// results only after it is destroyed, so failures are printed.
//
class SuppressStdout
{
  public:
	SuppressStdout() noexcept
	{
		std::fflush(stdout);
		m_saved = _dup(_fileno(stdout));
		FILE* ignored{};
		freopen_s(&ignored, "NUL", "w", stdout);
	}

	~SuppressStdout() noexcept
	{
		std::fflush(stdout);
		_dup2(m_saved, _fileno(stdout));
		_close(m_saved);
	}

	SuppressStdout(const SuppressStdout&) = delete;
	SuppressStdout&
	operator=(const SuppressStdout&) = delete;

  private:
	int m_saved{-1};
};

//
// CaptureStdout
//
// Sends stdout to a scratch file in the current directory while it exists, so a test can check the
// deletion headers and prompts. Read the text with Finish, which also restores stdout; check results
// only after that, so failures are printed.
//
class CaptureStdout
{
  public:
	CaptureStdout() noexcept
	{
		std::fflush(stdout);
		m_saved = _dup(_fileno(stdout));
		FILE* ignored{};
		freopen_s(&ignored, CaptureFileName, "w", stdout);
	}

	~CaptureStdout() noexcept
	{
		Restore();
		std::remove(CaptureFileName);
	}

	//
	// Finish
	//
	// Restores stdout and reads what was printed.
	//
	// Returns:
	//   Everything printed to stdout since the capture started.
	//
	std::string
	Finish()
	{
		Restore();
		std::string text;
		FILE* file{};
		if (fopen_s(&file, CaptureFileName, "r") == 0 && file)
		{
			char buffer[4096];
			size_t read{};
			while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0)
			{
				text.append(buffer, read);
			}
			std::fclose(file);
		}
		std::remove(CaptureFileName);
		return text;
	}

	CaptureStdout(const CaptureStdout&) = delete;
	CaptureStdout&
	operator=(const CaptureStdout&) = delete;

  private:
	static constexpr auto* CaptureFileName = "FirewallRulePrintTests-stdout.txt";

	//
	// Restore
	//
	// Points stdout back where it was, once; this also closes the scratch file.
	//
	void
	Restore() noexcept
	{
		if (m_saved != -1)
		{
			std::fflush(stdout);
			_dup2(m_saved, _fileno(stdout));
			_close(m_saved);
			m_saved = -1;
		}
	}

	int m_saved{-1};
};

//
// RunDeleteDuplicateRules
//
// Runs DeleteDuplicateRules over the sets of MakeDuplicateRules with scripted answers and a fake delete
// function. The sets are, in order: {d5};{d6} (no names), {d3} "Another";{d4} "beta-long-name", and
// {d1};{d2} (both "zz").
//
// Parameters:
//   answers    [in] - the user's input, one answer per line
//   failing_id [in] - a rule ID the fake fails to delete with ERROR_ACCESS_DENIED, or nullptr
//
// Returns:
//   The rule IDs the fake was asked to delete, in order, each followed by ';'. Also checks that exactly
//   the rules deleted without failure are marked is_rule_deleted.
//
std::wstring
RunDeleteDuplicateRules(const wchar_t* answers, const wchar_t* failing_id = nullptr)
{
	const auto fw_rules = MakeDuplicateRules();
	auto rules = NormalizeRules(fw_rules);
	const auto analysis = AnalyzeDuplicateRules(rules);
	std::wistringstream input(answers);
	std::wstring attempted;
	std::wstring expected_deleted;
	StoreCleanup cleanup;
	g_recorded_failures.clear();
	{
		SuppressStdout quiet;
		DeleteDuplicateRules(
		    analysis,
		    input,
		    [&](PCWSTR rule_id) -> DWORD
		    {
			    attempted += rule_id;
			    attempted += L';';
			    if (failing_id && std::wstring_view(rule_id) == failing_id)
			    {
				    return ERROR_ACCESS_DENIED;
			    }
			    expected_deleted += rule_id;
			    expected_deleted += L';';
			    return ERROR_SUCCESS;
		    },
		    cleanup);
	}

	std::wstring marked_deleted;
	for (const auto& set : analysis.duplicateSets)
	{
		for (auto rule = set.duplicate_rule_begin; rule != set.duplicate_rule_end; ++rule)
		{
			if (rule->is_rule_deleted)
			{
				marked_deleted += rule->fw_rule->wszRuleId;
				marked_deleted += L';';
			}
		}
	}
	Check(marked_deleted == expected_deleted, "exactly the rules deleted without failure are marked deleted");
	return attempted;
}

//
// TestDeleteDuplicateRules
//
// Checks which rules DeleteDuplicateRules deletes for each answer, which rule it keeps, that running out
// of input never deletes anything more, and that a failed deletion is recorded.
//
void
TestDeleteDuplicateRules()
{
	Check(
	    RunDeleteDuplicateRules(L"y\nn\ny\n") == L"{d6};{d2};",
	    "'y' deletes all but the first rule of a set when the names match; 'n' deletes nothing from that set");
	Check(
	    RunDeleteDuplicateRules(L"n\ny\n1\nn\n") == L"{d4};",
	    "choosing the first name keeps the rule with that name");
	Check(
	    RunDeleteDuplicateRules(L"a\n2\n") == L"{d6};{d3};{d2};",
	    "'a' deletes from every set without asking again, but still asks which name to keep");
	Check(RunDeleteDuplicateRules(L"y\ns\n") == L"{d6};", "'s' deletes nothing more from the store");
	Check(RunDeleteDuplicateRules(L"Y\nx\nN\nS\n") == L"{d6};", "answers are case-insensitive; others ask again");
	Check(RunDeleteDuplicateRules(L"") == L"", "no input deletes nothing");
	Check(
	    RunDeleteDuplicateRules(L"n\ny\nx\n0\n9\n") == L"",
	    "numbers that are not listed ask again; running out of input keeps the set and skips the rest");
	Check(g_recorded_failures.empty(), "no failure is recorded when every deletion succeeds");

	Check(
	    RunDeleteDuplicateRules(L"a\n1\n", L"{d4}") == L"{d6};{d4};{d2};",
	    "a failed deletion does not stop the remaining deletions");
	Check(
	    g_recorded_failures.size() == 1 && g_recorded_failures[0] == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED),
	    "a failed deletion is recorded as an HRESULT");
}

wchar_t g_deleted_copy_id[] = L"{d0}";

//
// MakeRulesWithDeletedDuplicates
//
// Returns:
//   The rules of MakeDuplicateRules plus a third UDP "zz" copy {d0}, which sorts first in its set. Mark
//   rules deleted with MarkRulesDeleted after normalizing them.
//
std::vector<FW_RULE>
MakeRulesWithDeletedDuplicates()
{
	auto fw_rules = MakeDuplicateRules();
	auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	fw_rule.wIpProtocol = IPPROTO_UDP;
	fw_rule.wszName = g_zz_lower_name;
	fw_rule.wszRuleId = g_deleted_copy_id;
	fw_rules.push_back(fw_rule);
	return fw_rules;
}

//
// MarkRulesDeleted
//
// Marks {d0} and {d6} is_rule_deleted, as an earlier -clean-rules phase would. That leaves the UDP set
// {d0};{d1};{d2} with two live rules (the deleted one sorting first), and the outbound set {d5};{d6}
// with one (the deleted one sorting last).
//
// Parameters:
//   rules [in, out] - rules normalized from MakeRulesWithDeletedDuplicates
//
void
MarkRulesDeleted(std::vector<NormalizedFirewallRule>& rules)
{
	for (auto& rule : rules)
	{
		const std::wstring_view rule_id = rule.fw_rule->wszRuleId;
		if (rule_id == g_deleted_copy_id || rule_id == g_duplicate_rule_ids[5])
		{
			rule.is_rule_deleted = true;
		}
	}
}

//
// MarkedDeletedIds
//
// Parameters:
//   rules [in] - rules normalized from MakeRulesWithDeletedDuplicates
//
// Returns:
//   The rule IDs of the rules marked is_rule_deleted, sorted, each followed by ';'.
//
std::wstring
MarkedDeletedIds(const std::vector<NormalizedFirewallRule>& rules)
{
	std::vector<std::wstring> ids;
	for (const auto& rule : rules)
	{
		if (rule.is_rule_deleted)
		{
			ids.emplace_back(rule.fw_rule->wszRuleId);
		}
	}
	std::ranges::sort(ids);
	std::wstring text;
	for (const auto& id : ids)
	{
		text += id + L";";
	}
	return text;
}

//
// TestDuplicateAnalysisSkipsDeletedRules
//
// Checks that rules already marked is_rule_deleted are left out of the sets and the count, that a set
// left with one live rule is not reported, and that a set's first rule (the one kept by default) is live.
//
void
TestDuplicateAnalysisSkipsDeletedRules()
{
	const auto fw_rules = MakeRulesWithDeletedDuplicates();
	auto rules = NormalizeRules(fw_rules);
	MarkRulesDeleted(rules);
	const auto analysis = AnalyzeDuplicateRules(rules);

	Check(
	    analysis.duplicateSets.size() == 2 && analysis.duplicateRuleCount == 4,
	    "deleted rules are not counted, and a set with one live rule left is not a set of duplicates");
	bool any_deleted_in_a_set = false;
	bool lone_live_rule_in_a_set = false;
	for (const auto& set : analysis.duplicateSets)
	{
		for (auto rule = set.duplicate_rule_begin; rule != set.duplicate_rule_end; ++rule)
		{
			any_deleted_in_a_set = any_deleted_in_a_set || rule->is_rule_deleted;
			lone_live_rule_in_a_set =
			    lone_live_rule_in_a_set || std::wstring_view(rule->fw_rule->wszRuleId) == g_duplicate_rule_ids[4];
		}
	}
	Check(!any_deleted_in_a_set, "no set contains a rule already deleted");
	Check(!lone_live_rule_in_a_set, "the one live rule left of a set is not in any set");
	if (analysis.duplicateSets.size() != 2)
	{
		return;
	}
	Check(
	    RuleIdsOf(analysis.duplicateSets[0]) == L"{d3};{d4};" && RuleIdsOf(analysis.duplicateSets[1]) == L"{d1};{d2};",
	    "the live rules of a set with a deleted rule are still a set, and its first rule is live");
	Check(
	    rules.size() >= 2 && rules[rules.size() - 1].is_rule_deleted && rules[rules.size() - 2].is_rule_deleted,
	    "the deleted rules are sorted after the rules not deleted");
	Check(
	    PrintDuplicateAnalysis(analysis, AnalysisOutput::Summary) ==
	        L"  * Summary of duplicate analysis of firewall rules:\n"
	        L"   - count of sets of duplicate rules: 2\n"
	        L"   - count of rules in sets of duplicate rules: 4\n",
	    "the summary counts only the live rules");
}

//
// TestDeleteDuplicateRulesSkipsDeletedRules
//
// Checks that DeleteDuplicateRules, after an earlier phase deleted some copies, never deletes a rule
// again, keeps a live rule of each set, and deletes the other live copies.
//
void
TestDeleteDuplicateRulesSkipsDeletedRules()
{
	const auto fw_rules = MakeRulesWithDeletedDuplicates();
	auto rules = NormalizeRules(fw_rules);
	MarkRulesDeleted(rules);
	const auto analysis = AnalyzeDuplicateRules(rules);
	std::wistringstream input(L"a\n1\n");
	std::wstring attempted;
	StoreCleanup cleanup;
	g_recorded_failures.clear();
	{
		SuppressStdout quiet;
		DeleteDuplicateRules(
		    analysis,
		    input,
		    [&attempted](PCWSTR rule_id) -> DWORD
		    {
			    attempted += rule_id;
			    attempted += L';';
			    return ERROR_SUCCESS;
		    },
		    cleanup);
	}

	Check(
	    attempted.find(g_deleted_copy_id) == std::wstring::npos &&
	        attempted.find(g_duplicate_rule_ids[5]) == std::wstring::npos,
	    "a rule already deleted is not deleted again");
	Check(
	    attempted.find(g_duplicate_rule_ids[0]) == std::wstring::npos,
	    "a live rule is kept, not the deleted copy that sorts first in its set");
	Check(
	    attempted.find(g_duplicate_rule_ids[4]) == std::wstring::npos,
	    "the one live rule left of a set is not deleted");
	Check(attempted == L"{d4};{d2};", "the live copies that are not kept are deleted");
	Check(
	    MarkedDeletedIds(rules) == L"{d0};{d2};{d4};{d6};",
	    "the rules deleted earlier stay marked, and only the newly deleted rules are added");
	Check(g_recorded_failures.empty(), "no failure is recorded");
}

wchar_t g_clean_rule_ids[7][8]{L"{c1}", L"{c2}", L"{c3}", L"{c4}", L"{c5}", L"{c6}", L"{c7}"};

// DeleteMissingAppRules or DeleteUnresolvedUserAccountRules
using DeleteRulesFunction =
    void (*)(std::vector<NormalizedFirewallRule>&, std::wistream&, const DeleteFirewallRuleFunction&, StoreCleanup&);

//
// MakeCleanupRules
//
// Returns:
//   Seven rules {c1} to {c7}, each with a missing application and an owner SID, for the tests to set
//   their check results on after normalizing them.
//
std::vector<FW_RULE>
MakeCleanupRules()
{
	std::vector<FW_RULE> fw_rules;
	for (auto& rule_id : g_clean_rule_ids)
	{
		auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
		fw_rule.wszRuleId = rule_id;
		fw_rule.wszLocalApplication = g_missing_application;
		fw_rule.wszLocalUserOwner = g_unmapped_sid;
		fw_rules.push_back(fw_rule);
	}
	return fw_rules;
}

//
// SetMissingAppResults
//
// Sets the missing-application check results so that DeleteMissingAppRules offers {c1}, {c4}, and {c7}:
// {c1}, {c4}, {c7} missing; {c2} not checked; {c3} and {c6} found; {c5} missing but already deleted.
//
// Parameters:
//   rules [in, out] - rules normalized from MakeCleanupRules
//
void
SetMissingAppResults(std::vector<NormalizedFirewallRule>& rules)
{
	const std::optional<bool> exists[7]{false, std::nullopt, true, false, false, true, false};
	for (size_t index = 0; index < rules.size(); ++index)
	{
		rules[index].local_application_exists = exists[index];
	}
	rules[4].is_rule_deleted = true;
}

//
// SetUnresolvedOwnerResults
//
// Sets the owner check results so that DeleteUnresolvedUserAccountRules offers {c1}, {c4}, and {c7}:
// {c1} and {c7} unresolved; {c2} not checked; {c3} resolved, profile not checked; {c4} resolved without
// a local profile; {c5} unresolved but already deleted; {c6} resolved with a local profile.
//
// Parameters:
//   rules [in, out] - rules normalized from MakeCleanupRules
//
void
SetUnresolvedOwnerResults(std::vector<NormalizedFirewallRule>& rules)
{
	const std::optional<bool> resolved[7]{false, std::nullopt, true, true, false, true, false};
	const std::optional<bool>
	    has_profile[7]{std::nullopt, std::nullopt, std::nullopt, false, std::nullopt, true, std::nullopt};
	for (size_t index = 0; index < rules.size(); ++index)
	{
		rules[index].successfully_resolved_user_name = resolved[index];
		rules[index].successfully_resolved_user_name_with_local_profile = has_profile[index];
	}
	rules[4].is_rule_deleted = true;
}

//
// RunDeleteRules
//
// Runs one deletion phase over rules with scripted answers and a fake delete function.
//
// Parameters:
//   deleteRules [in]      - DeleteMissingAppRules or DeleteUnresolvedUserAccountRules
//   rules       [in, out] - the rules to delete from; deleted rules are marked is_rule_deleted
//   answers     [in]      - the user's input, one answer per line
//   failing_id  [in]      - a rule ID the fake fails to delete with ERROR_ACCESS_DENIED, or nullptr
//   cleanup     [in, out] - receives the actions recorded, or nullptr to discard them
//
// Returns:
//   The rule IDs the fake was asked to delete, in order, each followed by ';'. Also checks that exactly
//   the rules marked deleted before, and the rules deleted without failure, are marked is_rule_deleted.
//
std::wstring
RunDeleteRules(
    DeleteRulesFunction deleteRules,
    std::vector<NormalizedFirewallRule>& rules,
    const wchar_t* answers,
    const wchar_t* failing_id = nullptr,
    StoreCleanup* cleanup = nullptr)
{
	StoreCleanup discarded;
	std::vector<bool> deleted_before;
	for (const auto& rule : rules)
	{
		deleted_before.push_back(rule.is_rule_deleted);
	}

	std::wistringstream input(answers);
	std::wstring attempted;
	std::vector<std::wstring> deleted_now;
	g_recorded_failures.clear();
	{
		SuppressStdout quiet;
		deleteRules(
		    rules,
		    input,
		    [&](PCWSTR rule_id) -> DWORD
		    {
			    attempted += rule_id;
			    attempted += L';';
			    if (failing_id && std::wstring_view(rule_id) == failing_id)
			    {
				    return ERROR_ACCESS_DENIED;
			    }
			    deleted_now.emplace_back(rule_id);
			    return ERROR_SUCCESS;
		    },
		    cleanup ? *cleanup : discarded);
	}

	bool marks_match = true;
	for (size_t index = 0; index < rules.size(); ++index)
	{
		const bool expected = deleted_before[index] ||
		                      std::ranges::find(deleted_now, rules[index].fw_rule->wszRuleId) != deleted_now.end();
		marks_match = marks_match && rules[index].is_rule_deleted == expected;
	}
	Check(marks_match, "exactly the rules deleted earlier or deleted without failure are marked deleted");
	return attempted;
}

//
// TestDeleteCleanupRules
//
// Checks, for DeleteMissingAppRules and DeleteUnresolvedUserAccountRules, which rules each answer
// deletes, that rules not checked, OK, or already deleted are never offered, that running out of input
// deletes nothing more, and that a failed deletion is recorded and leaves the rule unmarked.
//
void
TestDeleteCleanupRules()
{
	const auto fw_rules = MakeCleanupRules();
	for (const auto& [deleteRules, setResults, phase] :
	     {std::tuple{&DeleteMissingAppRules, &SetMissingAppResults, "missing application: "},
	      std::tuple{&DeleteUnresolvedUserAccountRules, &SetUnresolvedOwnerResults, "unresolved owner: "}})
	{
		const auto run = [&](const wchar_t* answers, const wchar_t* failing_id = nullptr)
		{
			auto rules = NormalizeRules(fw_rules);
			setResults(rules);
			return RunDeleteRules(deleteRules, rules, answers, failing_id);
		};
		const auto check = [phase](bool condition, const char* description)
		{
			const auto text = std::string(phase) + description;
			Check(condition, text.c_str());
		};

		check(run(L"y\nn\ny\n") == L"{c1};{c7};", "'y' deletes the rule; 'n' keeps it and asks about the next");
		check(
		    run(L"n\nn\ny\n") == L"{c7};",
		    "rules not checked, OK, or already deleted are never offered, so the third answer is the third offer");
		check(run(L"n\na\n") == L"{c4};{c7};", "'a' deletes this and every remaining rule without asking again");
		check(run(L"y\ns\ny\n") == L"{c1};", "'s' deletes nothing more");
		check(run(L"Y\nx\nN\nS\n") == L"{c1};", "answers are case-insensitive; others ask again");
		check(run(L"") == L"", "no input deletes nothing");
		check(run(L"y\n") == L"{c1};", "running out of input counts as 's'");
		check(g_recorded_failures.empty(), "no failure is recorded when every deletion succeeds");

		check(run(L"a\n", L"{c4}") == L"{c1};{c4};{c7};", "a failed deletion does not stop the remaining deletions");
		check(
		    g_recorded_failures.size() == 1 && g_recorded_failures[0] == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED),
		    "a failed deletion is recorded as an HRESULT");
	}
}

//
// TestCleanupPhasesSkipRulesDeletedEarlier
//
// Checks that a rule with both a missing application and an unresolved owner, deleted by
// DeleteMissingAppRules, is not offered again by DeleteUnresolvedUserAccountRules, and that it is offered
// again when its deletion failed.
//
void
TestCleanupPhasesSkipRulesDeletedEarlier()
{
	auto fw_rules = MakeCleanupRules();
	fw_rules.resize(2);
	for (const auto failing_id : {static_cast<const wchar_t*>(nullptr), static_cast<const wchar_t*>(L"{c1}")})
	{
		auto rules = NormalizeRules(fw_rules);
		// {c1} offends both checks, {c2} only the owner check
		rules[0].local_application_exists = false;
		rules[1].local_application_exists = true;
		rules[0].successfully_resolved_user_name = false;
		rules[1].successfully_resolved_user_name = false;

		const auto app_attempted = RunDeleteRules(&DeleteMissingAppRules, rules, L"y\n", failing_id);
		const auto owner_attempted = RunDeleteRules(&DeleteUnresolvedUserAccountRules, rules, L"y\nn\n");
		if (!failing_id)
		{
			Check(
			    app_attempted == L"{c1};" && owner_attempted == L"{c2};",
			    "a rule deleted for its missing application is not offered again for its owner");
		}
		else
		{
			Check(
			    app_attempted == L"{c1};" && owner_attempted == L"{c1};",
			    "a rule whose deletion failed is offered again by the next phase");
		}
	}
}

//
// TestDuplicateDeletionWording
//
// Checks the header and prompt DeleteDuplicateRules prints: 'Y' and 'N' act on the duplicates of the
// rule prompted, 'A' on all duplicate rules, and the prompt asks about all duplicates of the rule.
//
void
TestDuplicateDeletionWording()
{
	const auto fw_rules = MakeDuplicateRules();
	auto rules = NormalizeRules(fw_rules);
	const auto analysis = AnalyzeDuplicateRules(rules);
	std::wistringstream input(L"n\nn\nn\n");
	std::string text;
	StoreCleanup cleanup;
	{
		CaptureStdout capture;
		DeleteDuplicateRules(
		    analysis,
		    input,
		    [](PCWSTR) -> DWORD
		    {
			    return ERROR_SUCCESS;
		    },
		    cleanup);
		text = capture.Finish();
	}

	const auto contains = [&text](std::string_view expected)
	{
		return text.find(expected) != std::string::npos;
	};
	Check(
	    contains("     Deleting duplicate rules - will prompt for input (y/n/s/a)\n"),
	    "duplicates: the header names the duplicate category");
	Check(
	    contains("     - indicate 'Y' to delete duplicates of the one rule prompted\n") &&
	        contains("     - indicate 'N' to not delete duplicates of the one rule prompted\n"),
	    "duplicates: 'Y' and 'N' act on the duplicates of the one rule prompted");
	Check(
	    contains("     - indicate 'A' to delete ALL duplicate rules from this store without further prompts\n"),
	    "duplicates: 'A' deletes all duplicate rules");
	Check(
	    contains("       Delete all duplicates of this rule (y/n/s/a)? ") && !contains("Delete this rule"),
	    "duplicates: the prompt asks about all duplicates of the rule");
}

//
// TestSingleRuleDeletionWording
//
// Checks the header and prompt DeleteMissingAppRules and DeleteUnresolvedUserAccountRules print: 'Y'
// and 'N' act on the one rule prompted, 'A' on the phase's category, the prompt asks about this rule,
// and nothing mentions duplicates. Also checks the unresolved-SID phase's 's' message.
//
void
TestSingleRuleDeletionWording()
{
	const auto fw_rules = MakeCleanupRules();
	for (const auto& [deleteRules, setResults, heading, category, phase] :
	     {std::tuple{
	          &DeleteMissingAppRules,
	          &SetMissingAppResults,
	          "Deleting rules with an application exe referencing non-existing file",
	          "rules with an application exe referencing non-existing file",
	          "missing application: "},
	      std::tuple{
	          &DeleteUnresolvedUserAccountRules,
	          &SetUnresolvedOwnerResults,
	          "Deleting rules with unresolved SIDs or SIDs without local profiles",
	          "rules with unresolved SIDs or SIDs without local profiles",
	          "unresolved owner: "}})
	{
		auto rules = NormalizeRules(fw_rules);
		setResults(rules);
		std::wistringstream input(L"n\ns\n");
		std::string text;
		StoreCleanup cleanup;
		{
			CaptureStdout capture;
			deleteRules(
			    rules,
			    input,
			    [](PCWSTR) -> DWORD
			    {
				    return ERROR_SUCCESS;
			    },
			    cleanup);
			text = capture.Finish();
		}

		const auto contains = [&text](std::string_view expected)
		{
			return text.find(expected) != std::string::npos;
		};
		const auto check = [phase](bool condition, const char* description)
		{
			const auto full_description = std::string(phase) + description;
			Check(condition, full_description.c_str());
		};
		check(
		    contains(std::format("     {} - will prompt for input (y/n/s/a)\n", heading)),
		    "the header names the category on one line");
		check(
		    contains("     - indicate 'Y' to delete the one rule prompted\n") &&
		        contains("     - indicate 'N' to not delete the one rule prompted\n"),
		    "'Y' and 'N' act on the one rule prompted");
		check(
		    contains(
		        std::format(
		            "     - indicate 'A' to delete ALL {} from this store without further prompts\n",
		            category)),
		    "'A' deletes all rules of the category");
		check(
		    contains("       Delete this rule (y/n/s/a)? ") && !contains("Delete all duplicates"),
		    "the prompt asks about this rule");
		check(!contains("uplicate"), "nothing mentions duplicates");
	}
}

//
// TestUnresolvedOwnerSkipWording
//
// Checks the message DeleteUnresolvedUserAccountRules prints when the answer is 's'.
//
void
TestUnresolvedOwnerSkipWording()
{
	const auto fw_rules = MakeCleanupRules();
	auto rules = NormalizeRules(fw_rules);
	SetUnresolvedOwnerResults(rules);
	std::wistringstream input(L"s\n");
	std::string text;
	StoreCleanup cleanup;
	{
		CaptureStdout capture;
		DeleteUnresolvedUserAccountRules(
		    rules,
		    input,
		    [](PCWSTR) -> DWORD
		    {
			    return ERROR_SUCCESS;
		    },
		    cleanup);
		text = capture.Finish();
	}
	Check(
	    text.find("       - Skipping the remainder of the rules with unresolved SIDs in this store\n") !=
	        std::string::npos,
	    "unresolved owner: 's' prints the skip message with a space after the dash");
}

//
// DescribeCleanup
//
// Parameters:
//   cleanup [in] - the actions recorded by the deletion functions
//
// Returns:
//   One line per action: the decision, the approval source, then each rule's ID and outcome, e.g.
//   "yes prompt {c1}=deleted". "eoi" is EndOfInput, "none" NotPrompted, and "-" no source or no attempt.
//
std::wstring
DescribeCleanup(const StoreCleanup& cleanup)
{
	constexpr PCWSTR decisions[]{L"yes", L"no", L"skip", L"all", L"eoi", L"none"};
	constexpr PCWSTR sources[]{L"-", L"prompt", L"all"};
	constexpr PCWSTR outcomes[]{L"kept", L"deleted", L"failed", L"-"};
	std::wstring text;
	for (const auto& action : cleanup.actions)
	{
		text += decisions[static_cast<size_t>(action.decision)];
		text += L' ';
		text += sources[static_cast<size_t>(action.approvalSource)];
		for (const auto& record : action.rules)
		{
			text += std::format(
			    L" {}={}",
			    record.ruleId.value_or(L"(none)"),
			    outcomes[static_cast<size_t>(record.outcome)]);
		}
		text += L'\n';
	}
	return text;
}

//
// CountsAre
//
// Parameters:
//   counts [in] - the result of CountCleanup
//   the rest [in] - the expected counts, in the order CleanupCounts declares them
//
// Returns:
//   Whether every count matches, and the invariants candidate == attempted + declined + skipped and
//   attempted == succeeded + failed hold.
//
bool
CountsAre(
    const CleanupCounts& counts,
    size_t candidate,
    size_t attempted,
    size_t succeeded,
    size_t failed,
    size_t declined,
    size_t skipped)
{
	return counts.candidate == candidate && counts.attempted == attempted && counts.succeeded == succeeded &&
	       counts.failed == failed && counts.declined == declined && counts.skipped == skipped &&
	       counts.candidate == counts.attempted + counts.declined + counts.skipped &&
	       counts.attempted == counts.succeeded + counts.failed;
}

//
// TestCleanupActionsForSingleRules
//
// Checks the actions DeleteMissingAppRules and DeleteUnresolvedUserAccountRules record: one per rule
// offered or left unprompted, none for rules not checked, OK, or already deleted, with the decision,
// approval source, outcome, error, and reason of each answer, and the counts CountCleanup makes of them.
//
void
TestCleanupActionsForSingleRules()
{
	const auto fw_rules = MakeCleanupRules();
	for (const auto& [deleteRules, setResults, reasons, phase] :
	     {std::tuple{
	          &DeleteMissingAppRules,
	          &SetMissingAppResults,
	          std::array{
	              CleanupReason::MissingApplication,
	              CleanupReason::MissingApplication,
	              CleanupReason::MissingApplication},
	          "missing application: "},
	      std::tuple{
	          &DeleteUnresolvedUserAccountRules,
	          &SetUnresolvedOwnerResults,
	          std::array{
	              CleanupReason::UnresolvedUserOwner,
	              CleanupReason::MissingLocalProfile,
	              CleanupReason::UnresolvedUserOwner},
	          "unresolved owner: "}})
	{
		const auto run = [&](const wchar_t* answers, const wchar_t* failing_id = nullptr)
		{
			auto rules = NormalizeRules(fw_rules);
			setResults(rules);
			StoreCleanup cleanup;
			RunDeleteRules(deleteRules, rules, answers, failing_id, &cleanup);
			return cleanup;
		};
		const auto check = [phase](bool condition, const char* description)
		{
			const auto text = std::string(phase) + description;
			Check(condition, text.c_str());
		};

		const auto yes_no = run(L"y\nn\ny\n");
		check(
		    DescribeCleanup(yes_no) == L"yes prompt {c1}=deleted\nno - {c4}=-\nyes prompt {c7}=deleted\n",
		    "'y' is approved by its prompt and deleted; 'n' is declined and not attempted");
		bool reasons_match = yes_no.actions.size() == reasons.size();
		bool single_rule_actions = true;
		for (size_t index = 0; reasons_match && index < reasons.size(); ++index)
		{
			const auto& action = yes_no.actions[index];
			reasons_match = action.reason == reasons[index];
			single_rule_actions = single_rule_actions && action.rules.size() == 1 && !action.keptRuleIndex &&
			                      !action.keepChoice && action.rules[0].error == S_OK;
		}
		check(reasons_match, "each action records why its rule was proposed");
		check(single_rule_actions, "each action holds one rule, with no kept rule, keep choice, or error");
		check(CountsAre(CountCleanup(yes_no), 3, 2, 2, 0, 1, 0), "the rule answered 'n' is counted as declined");

		const auto skip = run(L"y\ns\ny\n");
		check(
		    DescribeCleanup(skip) == L"yes prompt {c1}=deleted\nskip - {c4}=-\nnone - {c7}=-\n",
		    "after 's' the remaining rules are recorded as not prompted, not approved, and not attempted");
		check(CountsAre(CountCleanup(skip), 3, 1, 1, 0, 0, 2), "the rules after 's', and its own, are skipped");

		const auto all = run(L"n\na\n");
		check(
		    DescribeCleanup(all) == L"no - {c1}=-\nall prompt {c4}=deleted\nnone all {c7}=deleted\n",
		    "'a' is approved by its prompt; the rules after it are approved by that 'a' without a prompt");
		check(CountsAre(CountCleanup(all), 3, 2, 2, 0, 1, 0), "the rules deleted after 'a' are attempted");

		check(
		    DescribeCleanup(run(L"Y\nx\nN\nS\n")) == L"yes prompt {c1}=deleted\nno - {c4}=-\nskip - {c7}=-\n",
		    "case-insensitive answers record the same decisions; an invalid answer records nothing");

		const auto end_of_input = run(L"y\n");
		check(
		    DescribeCleanup(end_of_input) == L"yes prompt {c1}=deleted\neoi - {c4}=-\nnone - {c7}=-\n",
		    "the end of the input is recorded at the prompt it ended, and the rest are not prompted");
		check(CountsAre(CountCleanup(end_of_input), 3, 1, 1, 0, 0, 2), "rules left at the end of input are skipped");
		check(
		    DescribeCleanup(run(L"")) == L"eoi - {c1}=-\nnone - {c4}=-\nnone - {c7}=-\n",
		    "with no input at all, every rule is still recorded");

		const auto failed = run(L"a\n", L"{c4}");
		check(
		    DescribeCleanup(failed) == L"all prompt {c1}=deleted\nnone all {c4}=failed\nnone all {c7}=deleted\n",
		    "a failed deletion is recorded as failed");
		check(
		    failed.actions.size() == 3 && failed.actions[1].rules[0].error == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) &&
		        failed.actions[0].rules[0].error == S_OK && failed.actions[2].rules[0].error == S_OK,
		    "a failed deletion records the HRESULT of the delete function's error; the others record none");
		check(CountsAre(CountCleanup(failed), 3, 3, 2, 1, 0, 0), "a failed deletion is attempted and failed");
	}
}

//
// TestCleanupPromptEndOfInput
//
// Checks that the stream overload of PromptForDeletion reports the end of the input as EndOfInput, not
// as an answer, including after an invalid answer.
//
void
TestCleanupPromptEndOfInput()
{
	std::wistringstream empty(L"");
	std::wistringstream invalid(L"x\n");
	std::wistringstream yes(L"y\n");
	PromptResponse responses[3]{};
	{
		SuppressStdout quiet;
		responses[0] = PromptForDeletion(RuleDeletionPrompt, empty);
		responses[1] = PromptForDeletion(RuleDeletionPrompt, invalid);
		responses[2] = PromptForDeletion(RuleDeletionPrompt, yes);
	}
	Check(responses[0] == PromptResponse::EndOfInput, "no input returns EndOfInput");
	Check(responses[1] == PromptResponse::EndOfInput, "input ending after an invalid answer returns EndOfInput");
	Check(responses[2] == PromptResponse::Yes, "an answer is still returned");
}

//
// ReadToEndOfInput
//
// Reads a line from a stream that holds no input, leaving it at its end with eofbit and failbit set.
//
// Parameters:
//   input [in, out] - the stream to read; must hold no input
//
void
ReadToEndOfInput(std::wistringstream& input)
{
	std::wstring line;
	std::getline(input, line);
}

//
// TestAskAgainAtEndOfInput
//
// Checks that a prompt asks again at the end of the input only at the console, where the stream is cleared
// so a later answer can be read, and that a scripted stream is never treated as the console.
//
void
TestAskAgainAtEndOfInput()
{
	std::wistringstream console(L"");
	ReadToEndOfInput(console);
	bool consoleAsksAgain{};
	{
		SuppressStdout quiet;
		consoleAsksAgain = AskAgainAtEndOfInput(console, true);
	}
	Check(consoleAsksAgain, "the end of the input at the console asks again");
	Check(console.good(), "asking again at the console clears the stream");
	console.str(L"y\n");
	std::wstring answer;
	Check(static_cast<bool>(std::getline(console, answer)) && answer == L"y", "a later answer at the console is read");

	std::wistringstream redirected(L"");
	ReadToEndOfInput(redirected);
	Check(!AskAgainAtEndOfInput(redirected, false), "the end of redirected input does not ask again");
	Check(redirected.eof() && redirected.fail(), "redirected input is left ended and failed");

	std::wistringstream bad(L"");
	ReadToEndOfInput(bad);
	bad.setstate(std::ios_base::badbit);
	Check(!AskAgainAtEndOfInput(bad, true), "a bad stream does not ask again, even at the console");
	Check(bad.bad(), "a bad stream is left bad");

	std::wistringstream unread(L"y\n");
	Check(!AskAgainAtEndOfInput(unread, true), "a stream not at its end does not ask again");

	Check(!InputIsConsole(console), "a scripted stream is not the console");
}

//
// RunDuplicateCleanup
//
// Runs DeleteDuplicateRules with scripted answers and a fake delete function, recording its actions.
//
// Parameters:
//   fw_rules     [in] - MakeDuplicateRules or MakeRulesWithDeletedDuplicates
//   mark_deleted [in] - whether to apply MarkRulesDeleted before the analysis
//   answers      [in] - the user's input, one answer per line
//   failing_id   [in] - a rule ID the fake fails to delete with ERROR_ACCESS_DENIED, or nullptr
//
// Returns:
//   The actions recorded.
//
StoreCleanup
RunDuplicateCleanup(
    const std::vector<FW_RULE>& fw_rules,
    bool mark_deleted,
    const wchar_t* answers,
    const wchar_t* failing_id = nullptr)
{
	auto rules = NormalizeRules(fw_rules);
	if (mark_deleted)
	{
		MarkRulesDeleted(rules);
	}
	const auto analysis = AnalyzeDuplicateRules(rules);
	std::wistringstream input(answers);
	StoreCleanup cleanup;
	g_recorded_failures.clear();
	{
		SuppressStdout quiet;
		DeleteDuplicateRules(
		    analysis,
		    input,
		    [failing_id](PCWSTR rule_id) -> DWORD
		    {
			    return failing_id && std::wstring_view(rule_id) == failing_id ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
		    },
		    cleanup);
	}
	return cleanup;
}

//
// TestCleanupActionsForDuplicates
//
// Checks the actions DeleteDuplicateRules records, one per set in set order ({d5};{d6}, then {d3};{d4}
// whose names differ, then {d1};{d2}): the decision, approval source, and each rule's outcome; the kept
// rule's position; the keep choice, answered or ended by the input; a failed deletion; and that rules
// already deleted are not recorded.
//
void
TestCleanupActionsForDuplicates()
{
	const auto fw_rules = MakeDuplicateRules();

	const auto yes_no = RunDuplicateCleanup(fw_rules, false, L"y\nn\ny\n");
	Check(
	    DescribeCleanup(yes_no) ==
	        L"yes prompt {d5}=kept {d6}=deleted\nno - {d3}=- {d4}=-\nyes prompt {d1}=kept {d2}=deleted\n",
	    "duplicates: each set is one action; the kept rule is recorded as kept");
	Check(
	    yes_no.actions.size() == 3 && yes_no.actions[0].keptRuleIndex == 0 && !yes_no.actions[1].keptRuleIndex &&
	        yes_no.actions[2].keptRuleIndex == 0 && !yes_no.actions[0].keepChoice && !yes_no.actions[1].keepChoice &&
	        !yes_no.actions[2].keepChoice && yes_no.actions[0].reason == CleanupReason::Duplicate,
	    "duplicates: a declined set has no kept rule, and no keep choice is recorded when the names match");
	Check(
	    CountsAre(CountCleanup(yes_no), 3, 2, 2, 0, 1, 0),
	    "duplicates: every rule of a set but the one kept is counted");

	const auto chosen = RunDuplicateCleanup(fw_rules, false, L"a\n2\n");
	Check(
	    DescribeCleanup(chosen) == L"all prompt {d5}=kept {d6}=deleted\nnone all {d3}=deleted {d4}=kept\n"
	                               L"none all {d1}=kept {d2}=deleted\n",
	    "duplicates: the sets after 'a' are approved by it, and the rule chosen is kept");
	if (chosen.actions.size() == 3 && chosen.actions[1].keepChoice)
	{
		const auto& keepChoice = *chosen.actions[1].keepChoice;
		Check(
		    keepChoice.choices == std::vector<std::wstring>{L"another", L"beta-long-name"} && keepChoice.answer == 2u &&
		        chosen.actions[1].keptRuleIndex == 1,
		    "duplicates: the keep choice records the names offered and the number entered");
	}
	else
	{
		Check(false, "duplicates: a set whose names differ records its keep choice");
	}

	const auto keep_ended = RunDuplicateCleanup(fw_rules, false, L"n\ny\n");
	Check(
	    DescribeCleanup(keep_ended) == L"no - {d5}=- {d6}=-\nyes prompt {d3}=- {d4}=-\neoi - {d1}=- {d2}=-\n",
	    "duplicates: when the input ends at the keep choice no rule of the set is attempted or kept");
	Check(
	    keep_ended.actions.size() == 3 && keep_ended.actions[1].keepChoice &&
	        keep_ended.actions[1].keepChoice->choices.size() == 2 && !keep_ended.actions[1].keepChoice->answer &&
	        !keep_ended.actions[1].keptRuleIndex,
	    "duplicates: a keep choice the input ended records no answer and no kept rule");
	Check(
	    CountsAre(CountCleanup(keep_ended), 3, 0, 0, 0, 1, 2),
	    "duplicates: a set left at the keep choice is counted as skipped, not declined");

	Check(
	    DescribeCleanup(RunDuplicateCleanup(fw_rules, false, L"y\ns\n")) ==
	        L"yes prompt {d5}=kept {d6}=deleted\nskip - {d3}=- {d4}=-\nnone - {d1}=- {d2}=-\n",
	    "duplicates: after 's' the remaining sets are recorded as not prompted");
	Check(
	    DescribeCleanup(RunDuplicateCleanup(fw_rules, false, L"y\n")) ==
	        L"yes prompt {d5}=kept {d6}=deleted\neoi - {d3}=- {d4}=-\nnone - {d1}=- {d2}=-\n",
	    "duplicates: the end of the input is recorded at the prompt it ended");

	const auto failed = RunDuplicateCleanup(fw_rules, false, L"a\n1\n", L"{d4}");
	Check(
	    DescribeCleanup(failed) == L"all prompt {d5}=kept {d6}=deleted\nnone all {d3}=kept {d4}=failed\n"
	                               L"none all {d1}=kept {d2}=deleted\n",
	    "duplicates: a failed deletion is recorded as failed");
	Check(
	    failed.actions.size() == 3 && failed.actions[1].rules[1].error == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) &&
	        failed.actions[1].rules[0].error == S_OK,
	    "duplicates: a failed deletion records the HRESULT of the delete function's error");
	Check(CountsAre(CountCleanup(failed), 3, 3, 2, 1, 0, 0), "duplicates: a failed deletion is attempted and failed");

	const auto with_three = RunDuplicateCleanup(MakeRulesWithDeletedDuplicates(), false, L"a\n1\n", L"{d2}");
	const auto three_rule_set = std::ranges::find_if(
	    with_three.actions,
	    [](const CleanupAction& action)
	    {
		    return action.rules.size() == 3;
	    });
	Check(
	    three_rule_set != with_three.actions.end() &&
	        DescribeCleanup({{*three_rule_set}}) == L"none all {d0}=kept {d1}=deleted {d2}=failed\n",
	    "duplicates: a set partly deleted records each rule's own outcome");
	Check(
	    CountsAre(CountCleanup(with_three), 4, 4, 3, 1, 0, 0),
	    "duplicates: a set of three proposes two rules, one deleted and one failed");

	const auto after_earlier_phase = RunDuplicateCleanup(MakeRulesWithDeletedDuplicates(), true, L"a\n1\n");
	Check(
	    DescribeCleanup(after_earlier_phase) == L"all prompt {d3}=kept {d4}=deleted\nnone all {d1}=kept {d2}=deleted\n",
	    "duplicates: rules already deleted, and a set left with one live rule, are not recorded");
}

//
// TestCountCleanup
//
// Checks CountCleanup on hand-built actions: declined only for 'n', skipped for every other decision
// that attempted nothing, attempts counted from the outcomes, and every rule of a duplicate set but one.
//
void
TestCountCleanup()
{
	Check(CountsAre(CountCleanup({}), 0, 0, 0, 0, 0, 0), "no actions count nothing");

	const auto single = [](CleanupDecision decision, DeletionOutcome outcome = DeletionOutcome::NotAttempted)
	{
		CleanupAction action{.reason = CleanupReason::MissingApplication, .decision = decision};
		action.rules.push_back({.outcome = outcome});
		return action;
	};
	const auto duplicates = [](CleanupDecision decision, std::initializer_list<DeletionOutcome> outcomes)
	{
		CleanupAction action{.reason = CleanupReason::Duplicate, .decision = decision};
		for (const auto outcome : outcomes)
		{
			action.rules.push_back({.outcome = outcome});
		}
		return action;
	};
	constexpr auto none = DeletionOutcome::NotAttempted;

	Check(
	    CountsAre(CountCleanup({{single(CleanupDecision::No)}}), 1, 0, 0, 0, 1, 0),
	    "a rule answered 'n' is declined");
	bool skipped = true;
	for (const auto decision :
	     {CleanupDecision::SkipRemaining,
	      CleanupDecision::EndOfInput,
	      CleanupDecision::NotPrompted,
	      CleanupDecision::Yes,
	      CleanupDecision::DeleteAll})
	{
		skipped = skipped && CountsAre(CountCleanup({{single(decision)}}), 1, 0, 0, 0, 0, 1);
	}
	Check(skipped, "a rule not attempted for any reason but 'n' is skipped");
	Check(
	    CountsAre(CountCleanup({{duplicates(CleanupDecision::No, {none, none, none})}}), 2, 0, 0, 0, 2, 0),
	    "a declined set of three declines the two rules it proposed");
	Check(
	    CountsAre(CountCleanup({{duplicates(CleanupDecision::Yes, {none, none, none})}}), 2, 0, 0, 0, 0, 2),
	    "a set left at its keep choice skips the two rules it proposed");
	Check(
	    CountsAre(CountCleanup({{duplicates(CleanupDecision::Yes, {})}}), 0, 0, 0, 0, 0, 0),
	    "a set with no rules proposes nothing");

	StoreCleanup mixed;
	mixed.actions.push_back(single(CleanupDecision::Yes, DeletionOutcome::Succeeded));
	mixed.actions.push_back(single(CleanupDecision::NotPrompted, DeletionOutcome::Failed));
	mixed.actions.push_back(single(CleanupDecision::No));
	mixed.actions.push_back(single(CleanupDecision::SkipRemaining));
	mixed.actions.push_back(duplicates(
	    CleanupDecision::DeleteAll,
	    {DeletionOutcome::Kept, DeletionOutcome::Succeeded, DeletionOutcome::Failed}));
	mixed.actions.push_back(duplicates(CleanupDecision::No, {none, none}));
	Check(
	    CountsAre(CountCleanup(mixed), 7, 4, 2, 2, 2, 1),
	    "counts add up across actions, with declined and skipped kept apart");
}

//
// TestUserOwnerAnalysisSkipsDeletedRules
//
// Checks that AnalyzeUserOwnerRules neither counts nor flags rules already deleted by an earlier
// -clean-rules phase, whether their owner is unresolved or resolved without a local profile.
//
void
TestUserOwnerAnalysisSkipsDeletedRules()
{
	const auto fw_rules = MakeCleanupRules();
	auto rules = NormalizeRules(fw_rules);
	for (auto& rule : rules)
	{
		rule.successfully_resolved_user_name = false;
	}
	// {c4} resolved without a local profile, {c3} resolved with no profile check result yet
	rules[2].successfully_resolved_user_name = true;
	rules[3].successfully_resolved_user_name = true;
	rules[2].is_rule_deleted = true;
	rules[4].is_rule_deleted = true;

	const auto analysis = AnalyzeUserOwnerRules(rules, {.check = LocalProfileCheck::Completed});
	Check(analysis.localUserOwnerRuleCount == 5, "deleted rules are not counted as rules with an owner");
	Check(
	    analysis.unresolvedSidRules.size() == 4 && std::ranges::none_of(
	                                                   analysis.unresolvedSidRules,
	                                                   [](const auto& finding)
	                                                   {
		                                                   return std::wstring_view(finding.ruleId) == L"{c5}";
	                                                   }),
	    "a deleted rule with an unresolved owner is not reported");
	Check(!rules[4].unresolve_user_sid, "a deleted rule with an unresolved owner is not flagged");
	Check(
	    analysis.missingLocalProfileRules.size() == 1 && !rules[2].successfully_resolved_user_name_with_local_profile &&
	        rules[3].successfully_resolved_user_name_with_local_profile == false,
	    "a deleted rule without a local profile is neither reported nor flagged");
}

//
// TestCleanupConsoleTextAfterSkip
//
// Checks that recording the rules left after 's' or the end of input prints nothing: each deletion
// function's output ends with its skip message, and matches the output of a store where no rules were
// left. The missing-application output is also compared with the text printed before the actions were
// recorded.
//
void
TestCleanupConsoleTextAfterSkip()
{
	const auto capture_run = [](const auto& run)
	{
		CaptureStdout capture;
		run();
		return capture.Finish();
	};
	const auto ignore_deletions = [](PCWSTR) -> DWORD
	{
		return ERROR_SUCCESS;
	};

	const auto fw_rules = MakeCleanupRules();
	for (const auto& [deleteRules, setResults, uncheck, skipMessage, phase] :
	     {std::tuple{
	          &DeleteMissingAppRules,
	          &SetMissingAppResults,
	          +[](NormalizedFirewallRule& rule)
	          {
		          rule.local_application_exists.reset();
	          },
	          "       - Skipping the remainder of the rules with an application exe referencing non-existing file "
	          "in this store\n",
	          "missing application: "},
	      std::tuple{
	          &DeleteUnresolvedUserAccountRules,
	          &SetUnresolvedOwnerResults,
	          +[](NormalizedFirewallRule& rule)
	          {
		          rule.successfully_resolved_user_name.reset();
	          },
	          "       - Skipping the remainder of the rules with unresolved SIDs in this store\n",
	          "unresolved owner: "}})
	{
		for (const auto answers : {L"y\ns\n", L"y\n"})
		{
			const auto output = [&](bool last_rule_offered)
			{
				auto rules = NormalizeRules(fw_rules);
				setResults(rules);
				if (!last_rule_offered)
				{
					uncheck(rules[6]);
				}
				std::wistringstream input(answers);
				StoreCleanup cleanup;
				return capture_run(
				    [&]
				    {
					    deleteRules(rules, input, ignore_deletions, cleanup);
				    });
			};
			const auto text = output(true);
			const auto description = std::string(phase) + (answers[2] == L's' ? "'s'" : "the end of input") +
			                         " prints its skip message last, and nothing for the rules left";
			Check(text.ends_with(skipMessage) && text == output(false), description.c_str());
		}
	}

	auto rules = NormalizeRules(fw_rules);
	SetMissingAppResults(rules);
	std::wistringstream input(L"y\ns\n");
	StoreCleanup cleanup;
	const auto text = capture_run(
	    [&]
	    {
		    DeleteMissingAppRules(rules, input, ignore_deletions, cleanup);
	    });
	Check(
	    text == "     Deleting rules with an application exe referencing non-existing file - will prompt for input "
	            "(y/n/s/a)\n"
	            "     - indicate 'Y' to delete the one rule prompted\n"
	            "     - indicate 'N' to not delete the one rule prompted\n"
	            "     - indicate 'S' to SKIP deleting any more rules from this store\n"
	            "     - indicate 'A' to delete ALL rules with an application exe referencing non-existing file from "
	            "this store without further prompts\n"
	            "\n"
	            "     Application-exe:  'C:\\FwDiagnoseTest-missing\\app.exe'  [(no Rule Name) RuleId:  {c1}]\n"
	            "              Delete this rule (y/n/s/a)?        - Successfully deleted the firewall rule\n"
	            "\n"
	            "     Application-exe:  'C:\\FwDiagnoseTest-missing\\app.exe'  [(no Rule Name) RuleId:  {c4}]\n"
	            "              Delete this rule (y/n/s/a)?        - Skipping the remainder of the rules with an "
	            "application exe referencing non-existing file in this store\n",
	    "missing application: the output of an 's' run is the text printed before actions were recorded");

	for (const auto answers : {L"y\ns\n", L"y\n"})
	{
		const auto fw_duplicates = MakeDuplicateRules();
		auto duplicate_rules = NormalizeRules(fw_duplicates);
		const auto analysis = AnalyzeDuplicateRules(duplicate_rules);
		std::wistringstream duplicate_input(answers);
		StoreCleanup duplicate_cleanup;
		const auto duplicate_text = capture_run(
		    [&]
		    {
			    DeleteDuplicateRules(analysis, duplicate_input, ignore_deletions, duplicate_cleanup);
		    });
		const auto end_of_input = answers[2] != L's' ? "\n       - No more input\n" : "";
		Check(
		    duplicate_text.ends_with(
		        std::format(
		            "              Delete all duplicates of this rule (y/n/s/a)? {}"
		            "       - Skipping the remainder of the duplicate rules in this store\n",
		            end_of_input)) &&
		        duplicate_text.find("zz") == std::string::npos,
		    "duplicates: 's' or the end of input prints its skip message last, and nothing for the sets left");
	}
}

//
// TestCleanupRecordsSurviveReorderedRules
//
// Checks that the actions recorded by DeleteMissingAppRules and DeleteUnresolvedUserAccountRules still
// name the rules prompted after the store's rules are reordered, as AnalyzeDuplicateRules does in place
// between those phases and the JSON report.
//
void
TestCleanupRecordsSurviveReorderedRules()
{
	auto fw_rules = MakeCleanupRules();
	fw_rules[0].wszName = g_another_name;
	for (const auto& [deleteRules, setResults, phase] :
	     {std::tuple{&DeleteMissingAppRules, &SetMissingAppResults, "missing application: "},
	      std::tuple{&DeleteUnresolvedUserAccountRules, &SetUnresolvedOwnerResults, "unresolved owner: "}})
	{
		auto rules = NormalizeRules(fw_rules);
		setResults(rules);
		StoreCleanup cleanup;
		RunDeleteRules(deleteRules, rules, L"y\nn\ny\n", nullptr, &cleanup);

		std::ranges::reverse(rules);
		const auto analysis = AnalyzeDuplicateRules(rules);

		const auto check = [phase](bool condition, const char* description)
		{
			const auto text = std::string(phase) + description;
			Check(condition, text.c_str());
		};
		check(
		    analysis.duplicateSets.size() == 1 && std::wstring_view(rules[0].fw_rule->wszRuleId) != L"{c1}",
		    "the duplicate analysis reordered the rules");
		check(
		    DescribeCleanup(cleanup) == L"yes prompt {c1}=deleted\nno - {c4}=-\nyes prompt {c7}=deleted\n",
		    "after the rules are reordered, each record still names the rule it was recorded for");
		if (cleanup.actions.size() == 3)
		{
			const auto& first = cleanup.actions[0].rules[0];
			const auto& second = cleanup.actions[1].rules[0];
			check(
			    first.name == L"Another" && !second.name.has_value(),
			    "the record keeps the rule's name, or no name when the rule has none");
			check(
			    first.application == g_missing_application && first.localUserOwnerSid == g_unmapped_sid,
			    "the record keeps the rule's application and owner SID");
		}
	}
}

// a family name longer than the 64 characters an app-container name can have
wchar_t g_long_package_family_name[] =
    L"Contoso.ThisPackageFamilyNameIsLongerThanAnAppContainerNameCanBe_8wekyb3d8bbwe";
wchar_t g_package_identity_rule_ids[2][20]{L"{IDENTITY-RULE-0}", L"{IDENTITY-RULE-1}"};
wchar_t g_unchecked_application[] = L"C:\\FwDiagnoseTest-unchecked\\app.exe";
wchar_t g_unchecked_rule_name[] = L"Unchecked rule";

//
// ExpectedPackageId
//
// Derives the app-container SID string for a package family name with the Windows API, for comparison with
// the package ID a rule derives.
//
// Parameters:
//   family_name [in]  - the package family name
//   error       [out] - S_OK, or the failure deriving or converting the SID
//
// Returns:
//   The SID string; empty when error is a failure.
//
std::wstring
ExpectedPackageId(PCWSTR family_name, HRESULT& error)
{
	wil::unique_sid sid;
	error = DeriveAppContainerSidFromAppContainerName(family_name, sid.addressof());
	if (FAILED(error))
	{
		return {};
	}
	wil::unique_hlocal_string text;
	if (!ConvertSidToStringSidW(sid.get(), text.addressof()))
	{
		error = HRESULT_FROM_WIN32(GetLastError());
		return {};
	}
	return text.get();
}

bool
SamePackageIdentity(const std::optional<RulePackageIdentity>& left, const std::optional<RulePackageIdentity>& right)
{
	if (!left.has_value() || !right.has_value())
	{
		return left.has_value() == right.has_value();
	}
	return left->packageId == right->packageId && left->packageIdSource == right->packageIdSource &&
	       left->packageFamilyName == right->packageFamilyName && left->packageIdError == right->packageIdError;
}

void
TestRulePackageIdentity()
{
	HRESULT expected_error{};
	const auto expected_id = ExpectedPackageId(g_package_family_name, expected_error);
	Check(SUCCEEDED(expected_error) && expected_id.starts_with(L"S-1-15-2-"), "the test derives an app-container SID");

	// MakeRule sets only a package family name
	const auto family_only = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	const NormalizedFirewallRule derived{&family_only, FW_BINARY_VERSION_33};
	Check(
	    derived.package_identity.has_value() && derived.package_identity->packageId == expected_id &&
	        derived.package_identity->packageIdSource == PackageIdSource::DerivedFromFamilyName &&
	        derived.package_identity->packageFamilyName == g_package_family_name &&
	        derived.package_identity->packageIdError == S_OK,
	    "a rule with only a package family name derives its package ID from it");
	Check(
	    SamePackageIdentity(
	        NormalizedFirewallRule{&family_only, FW_BINARY_VERSION_33}.package_identity,
	        derived.package_identity),
	    "the derived package ID is the same every time");

	auto empty_id = family_only;
	empty_id.wszPackageId = g_empty_string;
	Check(
	    SamePackageIdentity(
	        NormalizedFirewallRule{&empty_id, FW_BINARY_VERSION_33}.package_identity,
	        derived.package_identity),
	    "an empty package ID is derived from the family name");

	auto both = family_only;
	both.wszPackageId = g_package_id;
	const NormalizedFirewallRule from_rule{&both, FW_BINARY_VERSION_33};
	Check(
	    from_rule.package_identity.has_value() && from_rule.package_identity->packageId == g_package_id &&
	        from_rule.package_identity->packageIdSource == PackageIdSource::Rule &&
	        from_rule.package_identity->packageFamilyName == g_package_family_name &&
	        from_rule.package_identity->packageIdError == S_OK,
	    "a rule's own package ID is used rather than derived");

	auto id_only = both;
	id_only.wszPackageFamilyName = nullptr;
	const NormalizedFirewallRule without_family{&id_only, FW_BINARY_VERSION_33};
	Check(
	    without_family.package_identity.has_value() && without_family.package_identity->packageId == g_package_id &&
	        without_family.package_identity->packageIdSource == PackageIdSource::Rule &&
	        !without_family.package_identity->packageFamilyName.has_value(),
	    "a rule with only a package ID has no package family name");

	auto invalid = family_only;
	invalid.wszPackageFamilyName = g_long_package_family_name;
	ExpectedPackageId(g_long_package_family_name, expected_error);
	Check(FAILED(expected_error), "an app-container SID cannot be derived from a name longer than 64 characters");
	const NormalizedFirewallRule not_derived{&invalid, FW_BINARY_VERSION_33};
	Check(
	    not_derived.package_identity.has_value() && !not_derived.package_identity->packageId.has_value() &&
	        not_derived.package_identity->packageIdSource == PackageIdSource::DerivedFromFamilyName &&
	        not_derived.package_identity->packageFamilyName == g_long_package_family_name &&
	        not_derived.package_identity->packageIdError == expected_error,
	    "a package ID that cannot be derived is absent and keeps the failure");

	auto no_package = family_only;
	no_package.wszPackageFamilyName = nullptr;
	Check(
	    !NormalizedFirewallRule{&no_package, FW_BINARY_VERSION_33}.package_identity.has_value(),
	    "a rule without a package has no package identity");
	Check(
	    !NormalizedFirewallRule{&family_only, FW_BINARY_VERSION_31}.package_identity.has_value(),
	    "a package family name the requested schema version cannot carry is ignored");
}

//
// TestFindingsKeepPackageIdentity
//
// The findings and deletion records copy the rule's package identity, so each still describes its own rule
// after the store's rules are reordered.
//
void
TestFindingsKeepPackageIdentity()
{
	std::vector<FW_RULE> fw_rules(2, MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP));
	for (size_t index = 0; index < fw_rules.size(); ++index)
	{
		fw_rules[index].wszRuleId = g_package_identity_rule_ids[index];
		fw_rules[index].wszLocalApplication = g_missing_application;
	}
	// fw_rules[0] has a missing package family name, so its package ID is derived, and an owner that is not a
	// SID string; fw_rules[1] has a missing package ID and an owner without a local profile
	fw_rules[0].wszPackageFamilyName = g_missing_package_family_name;
	fw_rules[0].wszLocalUserOwner = g_invalid_sid;
	fw_rules[1].wszPackageId = g_missing_package_id;
	fw_rules[1].wszPackageFamilyName = nullptr;
	auto rules = NormalizeRules(fw_rules);
	// set after normalization so the test does not depend on an account lookup
	fw_rules[1].wszLocalUserOwner = g_no_profile_sid;
	rules[1].successfully_resolved_user_name = true;
	rules[1].local_user_domain_name = L"CONTOSO";
	rules[1].local_user_owner_name = L"alice";
	const auto identity0 = rules[0].package_identity;
	const auto identity1 = rules[1].package_identity;
	Check(
	    identity0.has_value() && identity0->packageIdSource == PackageIdSource::DerivedFromFamilyName &&
	        identity1.has_value() && identity1->packageIdSource == PackageIdSource::Rule,
	    "the rules have different package identities");

	size_t lookupCount = 0;
	const auto applications = AnalyzeApplicationRules(rules, ApplicationFileCheck::Completed);
	const auto packages = AnalyzePackageRules(rules, S_OK, InstalledPackageLookups(lookupCount), {});
	const auto owners = AnalyzeUserOwnerRules(rules, {.check = LocalProfileCheck::Completed});
	const auto record0 = ReturnRuleDeletionRecord(rules[0]);
	const auto record1 = ReturnRuleDeletionRecord(rules[1]);
	std::ranges::reverse(rules);

	if (!RunningUnderWow64())
	{
		Check(
		    applications.missingApplicationRules.size() == 2 &&
		        SamePackageIdentity(applications.missingApplicationRules[0].packageIdentity, identity0) &&
		        SamePackageIdentity(applications.missingApplicationRules[1].packageIdentity, identity1),
		    "the application findings keep their rules' package identities");
	}
	Check(
	    packages.missingPackageRules.size() == 2 &&
	        packages.missingPackageRules[0].reference == PackageReference::PackageFamilyName &&
	        SamePackageIdentity(packages.missingPackageRules[0].packageIdentity, identity0) &&
	        packages.missingPackageRules[1].reference == PackageReference::PackageId &&
	        SamePackageIdentity(packages.missingPackageRules[1].packageIdentity, identity1),
	    "the package findings keep their rules' package identities");
	Check(
	    owners.unresolvedSidRules.size() == 1 &&
	        SamePackageIdentity(owners.unresolvedSidRules[0].packageIdentity, identity0) &&
	        owners.missingLocalProfileRules.size() == 1 &&
	        SamePackageIdentity(owners.missingLocalProfileRules[0].packageIdentity, identity1),
	    "the SID-owner findings keep their rules' package identities");
	Check(
	    SamePackageIdentity(record0.packageIdentity, identity0) &&
	        SamePackageIdentity(record1.packageIdentity, identity1),
	    "the deletion records keep their rules' package identities");
}

//
// TestApplicationAnalysisWithUncheckedApplication
//
// ExpandEnvironmentStringsW cannot be made to fail here, so the rule's fields are set the way
// CheckIfLocalApplicationExists sets them when the expansion fails: the file is not checked.
//
void
TestApplicationAnalysisWithUncheckedApplication()
{
	auto fw_rule = MakeRule(FW_BINARY_VERSION_33, IPPROTO_TCP);
	fw_rule.wszLocalApplication = g_unchecked_application;
	fw_rule.wszName = g_unchecked_rule_name;
	std::vector<NormalizedFirewallRule> rules;
	rules.emplace_back(&fw_rule, FW_BINARY_VERSION_33);
	rules[0].local_application_exists.reset();
	rules[0].local_application_lookup_error = S_OK;
	rules[0].local_application_expand_error = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
	rules[0].local_application_failure_string = "Failed to expand environment variables (0x80070008)";

	const auto analysis = AnalyzeApplicationRules(rules, ApplicationFileCheck::Completed);
	Check(analysis.applicationRuleCount == 1, "an unchecked application rule is still an application rule");
	Check(analysis.missingApplicationRules.empty(), "an unchecked application is not counted as missing");
	if (analysis.uncheckedApplicationRules.size() == 1)
	{
		const auto& unchecked = analysis.uncheckedApplicationRules[0];
		Check(
		    unchecked.reason == ApplicationFindingReason::EnvironmentExpansionFailed &&
		        unchecked.error == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY),
		    "an unchecked application keeps the expansion failure, not the lookup result");
	}
	else
	{
		Check(false, "the rule whose path could not be expanded is unchecked");
	}

	const std::wstring counts = std::wstring{ApplicationSummaryHeader} +
	                            L"   - count of rules with an application exe: 1\n" +
	                            L"   - count of rules with an application exe referencing non-existing file: 0\n";
	const std::wstring unchecked =
	    L"   - count of rules with an application exe that could not be checked: 1\n"
	    L"     Application-exe:  'C:\\FwDiagnoseTest-unchecked\\app.exe'  (Failed to expand environment variables "
	    L"(0x80070008)) [Rule Name:  unchecked rule]\n";
	Check(
	    PrintApplicationAnalysis(analysis, AnalysisOutput::Summary) == counts + unchecked,
	    "the summary prints the unchecked rules even when nothing is missing");
	Check(
	    PrintApplicationAnalysis(analysis, AnalysisOutput::Verbose) == counts + PerUserCountLine + L"0\n" + unchecked,
	    "verbose output prints the unchecked rules");
}

void
TestPackageAnalysisWithSidFailures()
{
	const AppContainerSidFailure familyFailure{L"Bad.Family_x", PackageNameKind::FamilyName, E_INVALIDARG};
	const AppContainerSidFailure fullFailure{
	    L"Bad.Full_1.0.0.0_x64__x",
	    PackageNameKind::FullName,
	    HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)};
	std::vector<NormalizedFirewallRule> none;
	size_t lookupCount = 0;

	const auto notLoaded =
	    AnalyzePackageRules(none, E_ACCESSDENIED, InstalledPackageLookups(lookupCount), {familyFailure, fullFailure});
	Check(notLoaded.sidFailures.empty(), "the SID failures are dropped when the installed packages were not loaded");
	const auto loaded =
	    AnalyzePackageRules(none, S_OK, InstalledPackageLookups(lookupCount), {fullFailure, familyFailure});
	Check(
	    loaded.sidFailures.size() == 2 && loaded.sidFailures[0].packageName == fullFailure.packageName &&
	        loaded.sidFailures[0].kind == PackageNameKind::FullName &&
	        loaded.sidFailures[0].error == fullFailure.error &&
	        loaded.sidFailures[1].packageName == familyFailure.packageName &&
	        loaded.sidFailures[1].kind == PackageNameKind::FamilyName &&
	        loaded.sidFailures[1].error == familyFailure.error,
	    "the SID failures are kept in order when the installed packages were loaded");

	const auto counts = PackageCounts(0, 0, 0, 0);
	const std::wstring familyLine =
	    L"   - WARNING: count of installed packages whose app-container SID could not be derived from the family "
	    L"name (rules naming them by package ID are reported as referencing a non-existing package): 1\n";
	const std::wstring fullLine =
	    L"   - count of installed packages whose app-container SID could not be derived from the full name (rules "
	    L"use the family name, so this does not affect the analysis): 1\n";

	const auto familyOnly = AnalyzePackageRules(none, S_OK, InstalledPackageLookups(lookupCount), {familyFailure});
	Check(
	    PrintPackageAnalysis(familyOnly, AnalysisOutput::Summary) == counts + familyLine,
	    "the summary warns about a family-name failure without listing the packages");
	Check(
	    PrintPackageAnalysis(familyOnly, AnalysisOutput::Verbose) ==
	        counts + familyLine + L"     'Bad.Family_x'  (0x80070057)\n",
	    "verbose output lists the packages whose family-name SID could not be derived");

	const auto fullOnly = AnalyzePackageRules(none, S_OK, InstalledPackageLookups(lookupCount), {fullFailure});
	Check(
	    PrintPackageAnalysis(fullOnly, AnalysisOutput::Summary) == counts,
	    "the summary does not mention a full-name failure");
	Check(
	    PrintPackageAnalysis(fullOnly, AnalysisOutput::Verbose) ==
	        counts + fullLine + L"     'Bad.Full_1.0.0.0_x64__x'  (0x80070057)\n",
	    "verbose output lists a full-name failure without a warning");

	Check(
	    PrintPackageAnalysis(loaded, AnalysisOutput::Verbose) == counts + familyLine +
	                                                                 L"     'Bad.Family_x'  (0x80070057)\n" + fullLine +
	                                                                 L"     'Bad.Full_1.0.0.0_x64__x'  (0x80070057)\n",
	    "verbose output lists family-name failures before full-name failures");
}
} // namespace
int
wmain()
{
	TestSameLabelsForEverySchemaVersionAndProtocol();
	TestPlaceholdersForFieldsTheSchemaVersionCannotCarry();
	TestPackageFamilyNameAccessor();
	TestEmptyAndNullText();
	TestEmptyConditionsPrintTheEffectivePolicy();
	TestPortsAndIcmpFollowTheProtocol();
	TestHexValues();
	TestPopulatedRulesPrintTheSameAcrossSchemaVersions();
	TestPrintRuleContentsValues();
	TestResolvedUserNameHasNoEmbeddedNull();
	TestApplicationAnalysisWithNoApplicationRules();
	TestApplicationAnalysisWithEveryKindOfApplicationRule();
	TestApplicationAnalysisWithNullFindingFields();
	TestPackageAnalysisWithNoPackageRules();
	TestPackageAnalysisWithEveryKindOfPackageRule();
	TestPackageAnalysisWithNullFindingFields();
	TestUserOwnerAnalysisWithNoOwnerRules();
	TestUserOwnerAnalysisWithEveryKindOfOwnerRule();
	TestUserOwnerAnalysisWithNullFindingFields();
	TestFilterRankingsGroupAndOrderRuleNames();
	TestFilterRankingsWithoutFilters();
	TestDuplicateAnalysisFindsAndOrdersSets();
	TestDuplicateAnalysisWithoutDuplicates();
	TestDuplicateKeepChoices();
	TestDeleteDuplicateRules();
	TestDuplicateAnalysisSkipsDeletedRules();
	TestDeleteDuplicateRulesSkipsDeletedRules();
	TestDeleteCleanupRules();
	TestCleanupPhasesSkipRulesDeletedEarlier();
	TestDuplicateDeletionWording();
	TestSingleRuleDeletionWording();
	TestUnresolvedOwnerSkipWording();
	TestCleanupActionsForSingleRules();
	TestCleanupPromptEndOfInput();
	TestAskAgainAtEndOfInput();
	TestCleanupActionsForDuplicates();
	TestCountCleanup();
	TestUserOwnerAnalysisSkipsDeletedRules();
	TestCleanupConsoleTextAfterSkip();
	TestCleanupRecordsSurviveReorderedRules();
	TestRulePackageIdentity();
	TestFindingsKeepPackageIdentity();
	TestApplicationAnalysisWithUncheckedApplication();
	TestPackageAnalysisWithSidFailures();

	std::printf("%d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
