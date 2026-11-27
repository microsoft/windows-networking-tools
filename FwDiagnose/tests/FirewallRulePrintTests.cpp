// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Verifies that NormalizedFirewallRule::PrintRule prints the same fields for every schema version and IP protocol,
// with placeholders for fields the rule's schema version or protocol cannot carry.

#include <algorithm>
#include <cstdio>
#include <format>
#include <string>
#include <utility>
#include <vector>

#include <wil/network.h>
#include <Windows.h>

#include "..\NormalizedFirewallRule.h"
#include "..\ApplicationAnalysis.h"
#include "..\PackageAnalysis.h"

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

	std::printf("%d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
