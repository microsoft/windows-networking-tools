// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <optional>
#include <vector>
#include <Windows.h>

struct FirewallPolicyObjects;
struct NormalizedFirewallRule;
struct RuleStatusCategory
{
	PCWSTR name;
	std::vector<const NormalizedFirewallRule*> rules;
};

struct RuleStatusCategories
{
	RuleStatusCategory partiallyIgnored{L"partially_ignored", {}};
	RuleStatusCategory ignored{L"ignored", {}};
	RuleStatusCategory parsingError{L"parsing_error", {}};
	RuleStatusCategory semanticError{L"semantic_error", {}};
	RuleStatusCategory runtimeError{L"runtime_error", {}};
	RuleStatusCategory unknown{L"unknown", {}};
};

enum class RuleStatusAnalysis : uint8_t
{
	Performed,
	NotPerformed
};

struct FirewallProfileDiagnostic
{
	std::wstring property;
	std::wstring operation;
	std::wstring message;
	std::wstring sourceProperty;
	HRESULT error{};
	std::optional<int32_t> unknownValue;
};

struct FirewallProfileData
{
	std::optional<std::wstring> name;
	std::optional<int32_t> enabled;
	std::optional<bool> blockAllInboundTraffic;
	std::optional<int32_t> defaultInboundAction;
	std::optional<int32_t> defaultOutboundAction;
	std::optional<int32_t> allowInboundRules;
	std::optional<int32_t> allowLocalFirewallRules;
	std::optional<int32_t> allowUserApps;
	std::optional<int32_t> allowUserPorts;
	std::optional<int32_t> allowUnicastResponseToMulticast;
	std::optional<std::vector<std::wstring>> disabledInterfaceAliases;
	std::vector<FirewallProfileDiagnostic> diagnostics;
};

bool
ProfileJsonReportEnabled() noexcept;
void
InitializeProfileJsonReport(PCWSTR path, const std::vector<PCWSTR>& arguments);
void
FinishProfileJsonReport(int exitCode);
void
WriteFirewallProfileJson(const FirewallProfileData& profile, PCWSTR command);
void
RecordProfileJsonFailure(PCWSTR command, HRESULT error, PCSTR message);
void
WriteFirewallRuleStatusJson(
    const FirewallPolicyObjects& policy,
    size_t noErrorCount,
    const RuleStatusCategories& categories,
    PCWSTR command,
    RuleStatusAnalysis analysis);
