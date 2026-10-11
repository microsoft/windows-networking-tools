// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ProfileJsonReport.h"
#include "FirewallRules.h"

#include <algorithm>
#include <cstdio>
#include <format>
#include <optional>
#include <span>
#include <string_view>

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <wil/com.h>
#include <wil/resource.h>

namespace
{
using namespace winrt::Windows::Data::Json;

wil::unique_hfile g_output;
JsonObject g_jsonReport{nullptr};
JsonArray g_jsonResults{nullptr};

JsonValue
String(std::wstring_view value)
{
	return JsonValue::CreateStringValue(value);
}

std::wstring
Timestamp()
{
	SYSTEMTIME time{};
	GetSystemTime(&time);
	return std::format(L"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
	                   time.wYear,
	                   time.wMonth,
	                   time.wDay,
	                   time.wHour,
	                   time.wMinute,
	                   time.wSecond,
	                   time.wMilliseconds);
}

// Windows::Data::Json::JsonObject is a refcounted object - not a deep copy
JsonObject
ReturnJsonDiagnosticObject(PCWSTR property, PCWSTR operation, HRESULT error, std::wstring_view message)
{
	JsonObject diagnostic;
	diagnostic.SetNamedValue(L"severity", String(L"error"));
	diagnostic.SetNamedValue(L"code", String(L"policy_property_read_failed"));
	diagnostic.SetNamedValue(L"message", String(message));
	diagnostic.SetNamedValue(L"operation", String(operation));

	JsonObject subject;
	subject.SetNamedValue(L"property", String(property));
	diagnostic.SetNamedValue(L"subject", subject);

	JsonObject details;
	details.SetNamedValue(L"domain", String(L"hresult"));
	details.SetNamedValue(L"code", JsonValue::CreateNumberValue(static_cast<uint32_t>(error)));
	details.SetNamedValue(L"hex", String(std::format(L"0x{:08X}", static_cast<uint32_t>(error))));
	diagnostic.SetNamedValue(L"error", details);

	return diagnostic;
}

enum class PolicyValueKind : uint8_t
{
	Boolean,
	Action
};

PCWSTR
State(int32_t code, PolicyValueKind kind)
{
	switch (kind)
	{
	case PolicyValueKind::Action:
	{
		switch (code)
		{
		case 0:
			return L"not_configured";
		case 2:
			return L"allow";
		case 4:
			return L"block";
		default:
			return L"unknown";
		}
	}

	case PolicyValueKind::Boolean:
	{
		switch (code)
		{
		case 0:
			return L"false";
		case 1:
			return L"true";
		case 2:
			return L"not_configured";
		default:
			return L"unknown";
		}
	}
	} // switch

	// should never get here
	WI_ASSERT(false);
	return L"unknown";
}

JsonObject
ReturnJsonCodedValueObject(const std::optional<int32_t>& code, PolicyValueKind kind)
{
	JsonObject value;
	value.SetNamedValue(L"code", code.has_value() ? JsonValue::CreateNumberValue(*code) : JsonValue::CreateNullValue());
	value.SetNamedValue(L"state", String(code.has_value() ? State(*code, kind) : L"unavailable"));
	return value;
}

bool
IsShieldsCommand(PCWSTR argument, PCWSTR command)
{
	const auto length = wcslen(command);
	if (_wcsnicmp(argument, command, length) != 0)
	{
		return false;
	}
	if (argument[length] == L'\0')
	{
		return true;
	}
	if (argument[length] != L':')
	{
		return false;
	}

	const auto* profile = argument + length + 1;
	return _wcsicmp(profile, L"public") == 0 || _wcsicmp(profile, L"private") == 0 || _wcsicmp(profile, L"domain") == 0;
}

// Windows::Data::Json::JsonObject is a refcounted object - not a deep copy
JsonObject
ReturnJsonResultObject(PCWSTR command)
{
	for (const auto& result : g_jsonResults)
	{
		auto object = result.GetObject();
		if (object.GetNamedString(L"command") == command)
		{
			return object;
		}
	}

	JsonObject result;
	result.SetNamedValue(L"command", String(command));
	result.SetNamedValue(L"status", String(L"partial"));

	JsonObject data;
	data.SetNamedValue(L"firewallProfiles", JsonArray{});
	data.SetNamedValue(L"stores", JsonArray{});
	result.SetNamedValue(L"data", data);

	JsonObject pending;
	pending.SetNamedValue(L"severity", String(L"warning"));
	pending.SetNamedValue(L"code", String(L"json_export_incomplete"));
	pending.SetNamedValue(
	    L"message",
	    String(L"Firewall-profile configuration and rule-status analysis are exported. Other console output for this "
	           L"command is not yet exported."));

	JsonArray diagnostics;
	diagnostics.Append(pending);

	result.SetNamedValue(L"diagnostics", diagnostics);
	g_jsonResults.Append(result);
	return result;
}

std::wstring
PrettifyJson(const IJsonValue& value, size_t depth = 0)
{
	const std::wstring indent(depth * 2, L' ');
	const std::wstring childIndent((depth + 1) * 2, L' ');

	std::wstring text = L"{\n";
	if (value.ValueType() == JsonValueType::Object)
	{
		const auto object = value.GetObject();
		if (object.Size() == 0)
		{
			return L"{}";
		}

		if (object.Size() == 2 && object.HasKey(L"code") && object.HasKey(L"state"))
		{
			return L"{ \"code\": " + std::wstring(object.GetNamedValue(L"code").Stringify()) + L", \"state\": " +
			       std::wstring(object.GetNamedValue(L"state").Stringify()) + L" }";
		}

		uint32_t index = 0;
		const auto append = [&](std::wstring_view key, const IJsonValue& member)
		{
			text += childIndent + std::wstring(String(key).Stringify()) + L": " + PrettifyJson(member, depth + 1);
			text += ++index < object.Size() ? L",\n" : L"\n";
		};

		const bool isProfile = object.HasKey(L"profile") && object.HasKey(L"policyStore") && object.HasKey(L"enabled");

		// clang-format off
	    constexpr std::wstring_view profileOrder[]{L"profile",
		                                           L"displayName",
		                                           L"policyStore",
		                                           L"enabled",
		                                           L"defaultInboundAction",
		                                           L"defaultOutboundAction",
		                                           L"blockAllInboundTraffic",
		                                           L"allowUserApps",
		                                           L"allowUnicastResponseToMulticast",
		                                           L"allowLocalFirewallRules",
		                                           L"allowInboundRules",
		                                           L"allowUserPorts",
		                                           L"disabledInterfaceAliases",
		                                           L"status",
		                                           L"diagnostics"};

		constexpr std::wstring_view categoryOrder[]{L"category",
		                                            L"count",
		                                            L"rules"};

		constexpr std::wstring_view ruleDetailsOrder[]{L"totalRuleCount",
		                                               L"errorRuleCount",
		                                               L"categories"};

		constexpr std::wstring_view storeOrder[]{L"store",
		                                         L"displayName",
		                                         L"ruleDetails",
		                                         L"ruleCount",
		                                         L"status",
		                                         L"reason",
		                                         L"diagnostics"};
		// clang-format on
		std::span<const std::wstring_view> fieldOrder;
		if (isProfile)
		{
			fieldOrder = profileOrder;
		}
		else if (object.HasKey(L"category") && object.HasKey(L"count"))
		{
			fieldOrder = categoryOrder;
		}
		else if (object.HasKey(L"totalRuleCount") && object.HasKey(L"errorRuleCount") && object.HasKey(L"categories"))
		{
			fieldOrder = ruleDetailsOrder;
		}
		else if (object.HasKey(L"store") && object.HasKey(L"displayName") && object.HasKey(L"status"))
		{
			fieldOrder = storeOrder;
		}

		for (const auto key : fieldOrder)
		{
			if (object.HasKey(key))
			{
				append(key, object.GetNamedValue(key));
			}
		}

		for (const auto& entry : object)
		{
			if (std::ranges::find(fieldOrder, std::wstring_view(entry.Key())) == fieldOrder.end())
			{
				append(entry.Key(), entry.Value());
			}
		}

		text += indent + L"}";
	}
	else if (value.ValueType() == JsonValueType::Array)
	{
		const auto array = value.GetArray();
		if (array.Size() == 0)
		{
			return L"[]";
		}

		for (uint32_t index = 0; index < array.Size(); ++index)
		{
			text += childIndent + PrettifyJson(array.GetAt(index), depth + 1);
			text += index + 1 < array.Size() ? L",\n" : L"\n";
		}

		text += indent + L"]";
	}
	else
	{
		text = std::wstring(value.Stringify());
	}

	return text;
}
} // namespace

bool
ProfileJsonReportEnabled() noexcept
{
	return static_cast<bool>(g_output);
}

void
InitializeProfileJsonReport(PCWSTR path, const std::vector<PCWSTR>& arguments)
{
	bool hasProfileCommand = false;
	bool verbose = false;
	JsonArray commands;
	for (const auto* argument : arguments)
	{
		if (_wcsicmp(argument, L"-verbose") == 0)
		{
			verbose = true;
			continue;
		}

		std::wstring command;
		if (_wcsicmp(argument, L"-analyze-rules") == 0)
		{
			command = L"analyze_rules";
		}
		else if (_wcsicmp(argument, L"-clean-rules") == 0)
		{
			command = L"clean_rules";
		}
		else if (IsShieldsCommand(argument, L"-enable-shields-up") ||
		         IsShieldsCommand(argument, L"-disable-shields-up"))
		{
			command = L"shields_up_change";
		}
		else
		{
			THROW_HR_MSG(
			    E_INVALIDARG,
			    "-json currently supports only -analyze-rules, -clean-rules, and Shields Up commands (plus -verbose).");
		}

		hasProfileCommand = true;
		commands.Append(String(command));
	}

	THROW_HR_IF_MSG(E_INVALIDARG, !hasProfileCommand, "-json requires a firewall-profile command.");

	g_output.reset(CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
	THROW_LAST_ERROR_IF_MSG(!g_output, "Could not open JSON output file: %ls", path);

	g_jsonReport = JsonObject{};
	g_jsonReport.SetNamedValue(L"schemaVersion", String(L"1.0"));
	g_jsonReport.SetNamedValue(L"tool", String(L"FwDiagnose"));

	GUID id{};
	THROW_IF_FAILED(CoCreateGuid(&id));
	wchar_t idString[39]{};
	THROW_HR_IF(E_UNEXPECTED, StringFromGUID2(id, idString, ARRAYSIZE(idString)) == 0);

	JsonObject run;
	run.SetNamedValue(L"id", String(idString));
	run.SetNamedValue(L"startedAt", String(Timestamp()));
	run.SetNamedValue(L"requestedCommands", commands);
	run.SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));

	g_jsonResults = JsonArray{};
	g_jsonReport.SetNamedValue(L"run", run);
	g_jsonReport.SetNamedValue(L"results", g_jsonResults);
	g_jsonReport.SetNamedValue(L"diagnostics", JsonArray{});
}

void
FinishProfileJsonReport(int exitCode)
{
	if (!ProfileJsonReportEnabled())
	{
		return;
	}

	auto run = g_jsonReport.GetNamedObject(L"run");
	run.SetNamedValue(L"finishedAt", String(Timestamp()));
	run.SetNamedValue(L"exitCode", JsonValue::CreateNumberValue(exitCode));
	run.SetNamedValue(L"status", String(exitCode == 0 ? L"partial" : L"failed"));

	const auto bytes = winrt::to_string(PrettifyJson(g_jsonReport) + L"\n");
	size_t offset = 0;
	while (offset < bytes.size())
	{
		const auto length = static_cast<DWORD>((std::min)(bytes.size() - offset, static_cast<size_t>(MAXDWORD)));
		DWORD written{};
		THROW_LAST_ERROR_IF_MSG(!WriteFile(g_output.get(), bytes.data() + offset, length, &written, nullptr),
		                        "Failed to write JSON output.");
		THROW_HR_IF_MSG(E_UNEXPECTED, written == 0, "JSON output write made no progress.");
		offset += written;
	}

	THROW_LAST_ERROR_IF_MSG(!FlushFileBuffers(g_output.get()), "Failed to flush JSON output.");

	g_output.reset();
	g_jsonResults = nullptr;
	g_jsonReport = nullptr;
}

void
WriteFirewallProfileJson(const FirewallProfileData& profile, PCWSTR command)
{
	if (!ProfileJsonReportEnabled())
	{
		return;
	}

	const auto& name = profile.name;
	std::wstring canonical = name.value_or(L"");
	if (_wcsicmp(canonical.c_str(), L"Public") == 0)
	{
		canonical = L"public";
	}
	else if (_wcsicmp(canonical.c_str(), L"Private") == 0)
	{
		canonical = L"private";
	}
	else if (_wcsicmp(canonical.c_str(), L"Domain") == 0)
	{
		canonical = L"domain";
	}

	JsonObject output;
	output.SetNamedValue(L"profile", name.has_value() ? String(canonical) : JsonValue::CreateNullValue());
	output.SetNamedValue(L"displayName", name.has_value() ? String(*name) : JsonValue::CreateNullValue());
	output.SetNamedValue(L"policyStore", String(L"ActiveStore"));

	output.SetNamedValue(L"enabled", ReturnJsonCodedValueObject(profile.enabled, PolicyValueKind::Boolean));
	output.SetNamedValue(L"defaultInboundAction", ReturnJsonCodedValueObject(profile.defaultInboundAction, PolicyValueKind::Action));
	output.SetNamedValue(L"defaultOutboundAction", ReturnJsonCodedValueObject(profile.defaultOutboundAction, PolicyValueKind::Action));
	output.SetNamedValue(L"allowInboundRules", ReturnJsonCodedValueObject(profile.allowInboundRules, PolicyValueKind::Boolean));
	output.SetNamedValue(L"allowLocalFirewallRules",
	                     ReturnJsonCodedValueObject(profile.allowLocalFirewallRules, PolicyValueKind::Boolean));
	output.SetNamedValue(L"allowUserApps", ReturnJsonCodedValueObject(profile.allowUserApps, PolicyValueKind::Boolean));
	output.SetNamedValue(L"allowUserPorts", ReturnJsonCodedValueObject(profile.allowUserPorts, PolicyValueKind::Boolean));
	output.SetNamedValue(L"allowUnicastResponseToMulticast",
	                     ReturnJsonCodedValueObject(profile.allowUnicastResponseToMulticast, PolicyValueKind::Boolean));

	const auto& aliases = profile.disabledInterfaceAliases;
	JsonArray aliasArray;
	if (aliases.has_value())
	{
		for (const auto& alias : *aliases)
		{
			aliasArray.Append(String(alias));
		}
	}
	output.SetNamedValue(L"disabledInterfaceAliases",
	                     aliases.has_value() ? IJsonValue(aliasArray) : IJsonValue(JsonValue::CreateNullValue()));

	const auto& shields_up = profile.blockAllInboundTraffic;
	JsonObject shieldsValue;
	shieldsValue.SetNamedValue(L"friendlyName", String(L"Shields-Up"));
	shieldsValue.SetNamedValue(L"value",
	                           shields_up.has_value() ? JsonValue::CreateBooleanValue(*shields_up)
	                                                  : JsonValue::CreateNullValue());
	output.SetNamedValue(L"blockAllInboundTraffic", shieldsValue);

	JsonArray diagnostics;
	for (const auto& recorded : profile.diagnostics)
	{
		auto diagnostic =
		    ReturnJsonDiagnosticObject(recorded.property.c_str(), recorded.operation.c_str(), recorded.error, recorded.message);

		if (recorded.unknownValue.has_value())
		{
			diagnostic.SetNamedValue(L"severity", String(L"warning"));
			diagnostic.SetNamedValue(L"code", String(L"unknown_policy_value"));
			diagnostic.Remove(L"error");
			diagnostic.GetNamedObject(L"subject")
			    .SetNamedValue(L"value", JsonValue::CreateNumberValue(*recorded.unknownValue));
		}

		if (!recorded.sourceProperty.empty())
		{
			diagnostic.GetNamedObject(L"subject").SetNamedValue(L"sourceProperty", String(recorded.sourceProperty));
		}

		diagnostic.GetNamedObject(L"subject")
		    .SetNamedValue(L"profile", name.has_value() ? String(canonical) : JsonValue::CreateNullValue());

		diagnostics.Append(diagnostic);
	}

	output.SetNamedValue(L"diagnostics", diagnostics);
	output.SetNamedValue(L"status", String(diagnostics.Size() == 0 ? L"completed" : L"partial"));

	// Windows::Data::Json::JsonObject is a refcounted object - not a deep copy
	JsonObject result = ReturnJsonResultObject(command);
	result.GetNamedObject(L"data").GetNamedArray(L"firewallProfiles").Append(output);
}

void
RecordProfileJsonFailure(PCWSTR command, HRESULT error, PCSTR message)
{
	if (!ProfileJsonReportEnabled())
	{
		return;
	}

	auto diagnostic = ReturnJsonDiagnosticObject(L"firewallProfiles", L"collect_firewall_profiles", error, winrt::to_hstring(message));
	diagnostic.SetNamedValue(L"code", String(L"firewall_profile_collection_failed"));

	if (command)
	{
		// Windows::Data::Json::JsonObject is a refcounted object - not a deep copy
		JsonObject result = ReturnJsonResultObject(command);
		result.SetNamedValue(L"status", String(L"failed"));
		result.GetNamedArray(L"diagnostics").Append(diagnostic);
	}
	else
	{
		g_jsonReport.GetNamedArray(L"diagnostics").Append(diagnostic);
	}
}

void
WriteFirewallRuleStatusJson(const FirewallPolicyObjects& policy,
                            size_t noErrorCount,
                            const RuleStatusCategories& categories,
                            PCWSTR command,
                            RuleStatusAnalysis analysisMode)
{
	if (!ProfileJsonReportEnabled())
	{
		return;
	}

	PCWSTR storeName = nullptr;
	switch (policy.store_type)
	{
	case FW_STORE_TYPE_LOCAL:
		storeName = L"local";
		break;
	case FW_STORE_TYPE_GPO:
		storeName = L"group_policy";
		break;
	case FW_STORE_TYPE_GP_RSOP:
		storeName = L"group_policy_rsop";
		break;
	case FW_STORE_TYPE_WSH_STATIC:
		storeName = L"service_hardening_static";
		break;
	case FW_STORE_TYPE_WSH_CONFIGURABLE:
		storeName = L"service_hardening_configurable";
		break;
	case FW_STORE_TYPE_IF_ISO:
		storeName = L"interface_isolation";
		break;
	case FW_STORE_TYPE_IF_ISO_DYNAMIC:
		storeName = L"interface_isolation_dynamic";
		break;
	case FW_STORE_TYPE_APP_ISO:
		storeName = L"application_isolation";
		break;
	case FW_STORE_TYPE_MDM:
		storeName = L"mdm";
		break;
	case FW_STORE_TYPE_TENANT_RESTRICTIONS:
		storeName = L"tenant_restrictions";
		break;
	default:
		THROW_HR_MSG(E_UNEXPECTED, "Unknown firewall policy store type.");
	}

	JsonObject store;
	store.SetNamedValue(L"store", String(storeName));
	store.SetNamedValue(L"displayName", String(winrt::to_hstring(policy.store_type_string)));

	JsonArray diagnostics;
	store.SetNamedValue(L"diagnostics", diagnostics);
	
    if (policy.store_type == FW_STORE_TYPE_GP_RSOP && policy.load_result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
	{
		store.SetNamedValue(L"status", String(L"not_present"));
		store.Remove(L"diagnostics");
	}
	else if (FAILED(policy.load_result))
	{
		store.SetNamedValue(L"status",
		                    String(policy.load_result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ? L"not_present"
		                           : policy.load_result == E_PENDING                              ? L"not_collected"
		                                                                                          : L"failed"));
		auto diagnostic =
		    ReturnJsonDiagnosticObject(L"rules",
		               L"load_firewall_rules",
		               policy.load_result,
		               L"Rules were not successfully collected for this store; no status analysis is available.");
		diagnostic.SetNamedValue(L"code", String(L"firewall_store_collection_unavailable"));
		diagnostic.GetNamedObject(L"subject").SetNamedValue(L"store", String(storeName));
		diagnostics.Append(diagnostic);
	}
	else if (analysisMode == RuleStatusAnalysis::NotPerformed && !policy.normalizedRules.empty())
	{
		store.SetNamedValue(L"status", String(L"skipped"));
		store.SetNamedValue(L"reason", String(L"store_cannot_be_modified_locally"));
	}
	else
	{
		store.SetNamedValue(L"status", String(L"completed"));
		if (analysisMode == RuleStatusAnalysis::NotPerformed)
		{
			store.SetNamedValue(L"ruleCount", JsonValue::CreateNumberValue(0));
		}
		else
		{
			JsonObject analysis;
			const auto errorRuleCount = policy.normalizedRules.size() - noErrorCount;
			analysis.SetNamedValue(L"totalRuleCount",
			                       JsonValue::CreateNumberValue(static_cast<double>(policy.normalizedRules.size())));
			analysis.SetNamedValue(L"errorRuleCount",
			                       JsonValue::CreateNumberValue(static_cast<double>(errorRuleCount)));
			
			const auto verbose = g_jsonReport.GetNamedObject(L"run").GetNamedBoolean(L"verbose");
			
		    JsonArray outputCategories;
			for (const auto* entry : {&categories.partiallyIgnored,
			                          &categories.ignored,
			                          &categories.parsingError,
			                          &categories.semanticError,
			                          &categories.runtimeError,
			                          &categories.unknown})
			{
				const auto& rules = entry->rules;
				if (rules.empty())
				{
					continue;
				}

				JsonObject category;
				category.SetNamedValue(L"category", String(entry->name));
				category.SetNamedValue(L"count", JsonValue::CreateNumberValue(static_cast<double>(rules.size())));
				if (verbose)
				{
					JsonArray details;
					for (const auto* rule : rules)
					{
						JsonObject detail;
						detail.SetNamedValue(L"ruleId",
						                     rule->fw_rule->wszRuleId ? String(rule->fw_rule->wszRuleId)
						                                              : JsonValue::CreateNullValue());
						detail.SetNamedValue(L"name",
						                     rule->fw_rule->wszName ? String(rule->fw_rule->wszName)
						                                            : JsonValue::CreateNullValue());
						JsonObject status;
						status.SetNamedValue(L"code", JsonValue::CreateNumberValue(rule->fw_rule->Status));
						status.SetNamedValue(L"state", String(entry->name));
						detail.SetNamedValue(L"status", status);
						detail.SetNamedValue(
						    L"statusHex",
						    String(std::format(L"0x{:08X}", static_cast<uint32_t>(rule->fw_rule->Status))));
						details.Append(detail);
					}

					category.SetNamedValue(L"rules", details);
				}

				outputCategories.Append(category);
			}

			analysis.SetNamedValue(L"categories", outputCategories);
			store.SetNamedValue(L"ruleDetails", analysis);
		}
	}
	ReturnJsonResultObject(command).GetNamedObject(L"data").GetNamedArray(L"stores").Append(store);
}
