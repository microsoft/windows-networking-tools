// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Verifies that NormalizedFirewallRule::PrintRule prints the same fields for every schema version and IP protocol,
// with placeholders for fields the rule's schema version or protocol cannot carry.

#include <algorithm>
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
	const auto empty = AnalyzePackageRules(none, S_OK, InstalledPackageLookups(lookupCount));
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
	const auto failed = AnalyzePackageRules(rules, E_ACCESSDENIED, InstalledPackageLookups(lookupCount));
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
	const auto analysis = AnalyzePackageRules(rules, S_OK, InstalledPackageLookups(lookupCount));
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
		    });
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
		    });
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
    void (*)(std::vector<NormalizedFirewallRule>&, std::wistream&, const DeleteFirewallRuleFunction&);

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
    const wchar_t* failing_id = nullptr)
{
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
		    });
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

	std::printf("%d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
