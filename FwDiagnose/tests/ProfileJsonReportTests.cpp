// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "..\ProfileJsonReport.cpp"

#include <stdexcept>

void
Check(bool condition, const char* message)
{
	if (!condition)
	{
		throw std::runtime_error(message);
	}
}

int
wmain(int argc, wchar_t** argv)
try
{
	const auto init = wil::CoInitializeEx();
	Check(argc == 2, "Expected an output path.");
	using namespace winrt::Windows::Data::Json;
	Check(IsShieldsCommand(L"-enable-shields-up:public", L"-enable-shields-up"), "Profile suffix rejected.");
	Check(
	    IsShieldsCommand(L"-disable-shields-up:PRIVATE", L"-disable-shields-up"),
	    "Case insensitive suffix rejected.");
	Check(!IsShieldsCommand(L"-enable-shields-up:invalid", L"-enable-shields-up"), "Invalid suffix accepted.");
	Check(!IsShieldsCommand(L"-enable-shields-up-extra", L"-enable-shields-up"), "Invalid command prefix accepted.");

	const auto unavailable = CodedValue(std::nullopt, PolicyValueKind::Boolean);
	Check(unavailable.GetNamedValue(L"code").ValueType() == JsonValueType::Null, "Unavailable code not null.");
	Check(unavailable.GetNamedString(L"state") == L"unavailable", "Unavailable state incorrect.");
	Check(
	    CodedValue(2, PolicyValueKind::Boolean).GetNamedString(L"state") == L"not_configured",
	    "Not configured lost.");
	Check(CodedValue(999, PolicyValueKind::Action).GetNamedNumber(L"code") == 999, "Unknown raw code lost.");
	JsonObject escaped;
	escaped.SetNamedValue(L"text", String(L"quote\" slash\\ newline\n \u03a9 \u4e2d"));
	const auto formatted = Pretty(escaped);
	Check(
	    JsonObject::Parse(formatted).GetNamedString(L"text") == L"quote\" slash\\ newline\n \u03a9 \u4e2d",
	    "Unicode or escaping failed round trip.");
	Check(
	    Pretty(CodedValue(1, PolicyValueKind::Boolean)) == L"{ \"code\": 1, \"state\": \"true\" }",
	    "Coded pair not inline.");
	JsonObject category;
	JsonArray ruleDetails;
	ruleDetails.Append(String(L"example-rule"));
	category.SetNamedValue(L"rules", ruleDetails);
	category.SetNamedValue(L"count", JsonValue::CreateNumberValue(1));
	category.SetNamedValue(L"category", String(L"parsing_error"));
	Check(
	    Pretty(category) ==
	        L"{\n  \"category\": \"parsing_error\",\n  \"count\": 1,\n  \"rules\": [\n    \"example-rule\"\n  ]\n}",
	    "Category fields are not in category/count/rules order.");
	category.Remove(L"rules");
	Check(
	    Pretty(category) == L"{\n  \"category\": \"parsing_error\",\n  \"count\": 1\n}",
	    "Nonverbose category fields are not in category/count order.");
	category.SetNamedValue(L"extraField", String(L"preserved"));
	Check(
	    JsonObject::Parse(Pretty(category)).GetNamedString(L"extraField") == L"preserved",
	    "Ordered formatting dropped an additional category field.");
	JsonObject analysis;
	analysis.SetNamedValue(L"categories", JsonArray{});
	analysis.SetNamedValue(L"errorRuleCount", JsonValue::CreateNumberValue(0));
	analysis.SetNamedValue(L"totalRuleCount", JsonValue::CreateNumberValue(733));
	Check(
	    Pretty(analysis) == L"{\n  \"totalRuleCount\": 733,\n  \"errorRuleCount\": 0,\n  \"categories\": []\n}",
	    "Status analysis fields are not in total/error/categories order.");
	analysis.SetNamedValue(L"extraField", String(L"preserved"));
	Check(
	    JsonObject::Parse(Pretty(analysis)).GetNamedString(L"extraField") == L"preserved",
	    "Ordered formatting dropped an additional status analysis field.");

	FirewallProfileData profile;
	profile.disabledInterfaceAliases.emplace();
	for (const auto* property :
	     {L"profile",
	      L"enabled",
	      L"defaultInboundAction",
	      L"defaultOutboundAction",
	      L"allowInboundRules",
	      L"allowLocalFirewallRules",
	      L"allowUserApps",
	      L"allowUserPorts",
	      L"allowUnicastResponseToMulticast",
	      L"blockAllInboundTraffic"})
	{
		profile.diagnostics.push_back(
		    {.property = property,
		     .operation = L"test_collection",
		     .message = L"Property read failed.",
		     .error = E_ACCESSDENIED});
	}
	InitializeProfileJsonReport(argv[1], {L"-analyze-rules"});
	WriteFirewallProfileJson(profile, L"analyze_rules");
	const auto output =
	    g_results.GetAt(0).GetObject().GetNamedObject(L"data").GetNamedArray(L"firewallProfiles").GetAt(0).GetObject();
	Check(output.GetNamedValue(L"profile").ValueType() == JsonValueType::Null, "Missing name not null.");
	Check(output.GetNamedObject(L"enabled").GetNamedString(L"state") == L"unavailable", "Missing enabled defaulted.");
	Check(
	    output.GetNamedObject(L"blockAllInboundTraffic").GetNamedValue(L"value").ValueType() == JsonValueType::Null,
	    "Failed Shields Up read defaulted.");
	Check(output.GetNamedArray(L"diagnostics").Size() == 10, "Missing property diagnostics incomplete.");
	Check(output.GetNamedArray(L"disabledInterfaceAliases").Size() == 0, "Documented null aliases not empty.");
	Check(output.GetNamedString(L"status") == L"partial", "Failures reported completed.");

	Check(
	    output.GetNamedArray(L"diagnostics").GetAt(0).GetObject().GetNamedObject(L"error").GetNamedNumber(L"code") ==
	        static_cast<uint32_t>(E_ACCESSDENIED),
	    "Collected failure code not preserved.");
	FirewallProfileData collected;
	collected.name = L"Public";
	collected.enabled = 999;
	collected.blockAllInboundTraffic = false;
	collected.defaultInboundAction = 2;
	collected.defaultOutboundAction = 4;
	collected.allowInboundRules = 0;
	collected.allowLocalFirewallRules = 1;
	collected.allowUserApps = 2;
	collected.allowUserPorts = 1;
	collected.allowUnicastResponseToMulticast = 0;
	collected.disabledInterfaceAliases = {L"test-interface"};
	collected.diagnostics.push_back(
	    {.property = L"enabled",
	     .operation = L"IWbemClassObject::Get",
	     .message = L"Unknown policy value.",
	     .sourceProperty = L"Enabled",
	     .unknownValue = 999});
	WriteFirewallProfileJson(collected, L"analyze_rules");
	const auto collectedOutput =
	    g_results.GetAt(0).GetObject().GetNamedObject(L"data").GetNamedArray(L"firewallProfiles").GetAt(1).GetObject();
	Check(collectedOutput.GetNamedString(L"profile") == L"public", "Collected profile name lost.");
	Check(collectedOutput.GetNamedObject(L"enabled").GetNamedNumber(L"code") == 999, "Collected unknown code lost.");
	Check(
	    !collectedOutput.GetNamedObject(L"blockAllInboundTraffic").GetNamedBoolean(L"value"),
	    "False Shields Up lost.");
	Check(
	    collectedOutput.GetNamedObject(L"defaultInboundAction").GetNamedString(L"state") == L"allow",
	    "Collected action lost.");
	Check(
	    collectedOutput.GetNamedObject(L"defaultOutboundAction").GetNamedNumber(L"code") == 4,
	    "Outbound action lost.");
	Check(collectedOutput.GetNamedObject(L"allowInboundRules").GetNamedNumber(L"code") == 0, "False setting lost.");
	Check(
	    collectedOutput.GetNamedObject(L"allowLocalFirewallRules").GetNamedNumber(L"code") == 1,
	    "True setting lost.");
	Check(
	    collectedOutput.GetNamedObject(L"allowUserApps").GetNamedString(L"state") == L"not_configured",
	    "Not configured lost.");
	Check(collectedOutput.GetNamedObject(L"allowUserPorts").GetNamedNumber(L"code") == 1, "User port setting lost.");
	Check(
	    collectedOutput.GetNamedObject(L"allowUnicastResponseToMulticast").GetNamedNumber(L"code") == 0,
	    "Multicast setting lost.");
	Check(
	    collectedOutput.GetNamedArray(L"disabledInterfaceAliases").GetAt(0).GetString() == L"test-interface",
	    "Collected alias lost.");
	const auto warning = collectedOutput.GetNamedArray(L"diagnostics").GetAt(0).GetObject();
	Check(
	    warning.GetNamedString(L"severity") == L"warning" && !warning.HasKey(L"error"),
	    "Unknown value warning absent.");
	Check(warning.GetNamedObject(L"subject").GetNamedString(L"sourceProperty") == L"Enabled", "Source property lost.");
	const auto profileText = Pretty(collectedOutput);
	size_t nextField = 0;
	for (const auto* key :
	     {L"profile",
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
	      L"diagnostics"})
	{
		const auto position = profileText.find(std::wstring(L"\n  \"") + key + L"\":", nextField);
		Check(position != std::wstring::npos, "Firewall profile fields are not in the required order.");
		nextField = position + 1;
	}
	Check(JsonObject::Parse(profileText).Size() == collectedOutput.Size(), "Ordered formatting lost profile fields.");
	collectedOutput.SetNamedValue(L"extraField", String(L"preserved"));
	Check(
	    JsonObject::Parse(Pretty(collectedOutput)).GetNamedString(L"extraField") == L"preserved",
	    "Ordered formatting dropped an additional profile field.");
	Check(
	    JsonObject::Parse(Pretty(output)).GetNamedValue(L"profile").ValueType() == JsonValueType::Null,
	    "Ordered formatting lost unavailable profile values.");

	FirewallPolicyObjects store;
	const RuleStatusCategories categories;
	Check(
	    std::wstring_view(categories.partiallyIgnored.name) == L"partially_ignored",
	    "Partially ignored category name incorrect.");
	Check(std::wstring_view(categories.ignored.name) == L"ignored", "Ignored category name incorrect.");
	Check(std::wstring_view(categories.parsingError.name) == L"parsing_error", "Parsing category name incorrect.");
	Check(std::wstring_view(categories.semanticError.name) == L"semantic_error", "Semantic category name incorrect.");
	Check(std::wstring_view(categories.runtimeError.name) == L"runtime_error", "Runtime category name incorrect.");
	Check(std::wstring_view(categories.unknown.name) == L"unknown", "Unknown category name incorrect.");
	store.store_type = FW_STORE_TYPE_LOCAL;
	store.store_type_string = "Local";
	store.load_result = S_OK;
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::NotPerformed);
	const auto stores = g_results.GetAt(0).GetObject().GetNamedObject(L"data").GetNamedArray(L"stores");
	Check(stores.GetAt(0).GetObject().GetNamedString(L"status") == L"completed", "Empty store not completed.");
	Check(stores.GetAt(0).GetObject().GetNamedNumber(L"ruleCount") == 0, "Empty store count missing.");
	Check(!stores.GetAt(0).GetObject().HasKey(L"ruleDetails"), "Empty store has details that were not collected.");
	store.load_result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::NotPerformed);
	Check(stores.GetAt(1).GetObject().GetNamedString(L"status") == L"not_present", "Absent store treated as empty.");
	Check(
	    stores.GetAt(1).GetObject().GetNamedArray(L"diagnostics").Size() == 1,
	    "Unexpected missing-store diagnostic suppressed.");
	store.load_result = E_ACCESSDENIED;
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::NotPerformed);
	const auto failedStore = stores.GetAt(2).GetObject();
	Check(failedStore.GetNamedString(L"status") == L"failed", "Access denial treated as empty.");
	Check(
	    failedStore.GetNamedArray(L"diagnostics")
	            .GetAt(0)
	            .GetObject()
	            .GetNamedObject(L"error")
	            .GetNamedNumber(L"code") == static_cast<uint32_t>(E_ACCESSDENIED),
	    "Store error code lost.");
	store.load_result = S_OK;
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	Check(
	    stores.GetAt(3).GetObject().GetNamedObject(L"ruleDetails").GetNamedArray(L"categories").Size() == 0,
	    "Nonverbose zero categories were not omitted.");
	const auto normalAnalysis = stores.GetAt(3).GetObject().GetNamedObject(L"ruleDetails");
	const auto normalStore = stores.GetAt(3).GetObject();
	Check(!normalStore.HasKey(L"statusAnalysis"), "Old store analysis field retained.");
	const auto storeText = Pretty(normalStore);
	size_t nextStoreField = 0;
	for (const auto* key : {L"store", L"displayName", L"ruleDetails", L"status", L"diagnostics"})
	{
		const auto position = storeText.find(std::wstring(L"\n  \"") + key + L"\":", nextStoreField);
		Check(position != std::wstring::npos, "Store fields are not in the required order.");
		nextStoreField = position + 1;
	}
	Check(JsonObject::Parse(storeText).Size() == normalStore.Size(), "Ordered formatting lost store fields.");
	Check(
	    normalAnalysis.GetNamedNumber(L"totalRuleCount") == 0 && normalAnalysis.GetNamedNumber(L"errorRuleCount") == 0,
	    "Nonverbose error count incorrect.");
	Check(!normalAnalysis.HasKey(L"noErrorRuleCount"), "Old nonverbose no-error count retained.");
	g_report.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(true));
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	const auto verboseCategories =
	    stores.GetAt(4).GetObject().GetNamedObject(L"ruleDetails").GetNamedArray(L"categories");
	const auto verboseAnalysis = stores.GetAt(4).GetObject().GetNamedObject(L"ruleDetails");
	Check(!stores.GetAt(4).GetObject().HasKey(L"statusAnalysis"), "Old verbose store analysis field retained.");
	Check(
	    verboseAnalysis.GetNamedNumber(L"totalRuleCount") == 0 &&
	        verboseAnalysis.GetNamedNumber(L"errorRuleCount") == 0,
	    "Verbose error count incorrect.");
	Check(!verboseAnalysis.HasKey(L"noErrorRuleCount"), "Old verbose no-error count retained.");
	Check(verboseCategories.Size() == 0, "Error-free verbose analysis contains zero-count categories.");
	store.store_type = FW_STORE_TYPE_GP_RSOP;
	store.store_type_string = "Group Policy (RSOP)";
	for (const bool verbose : {false, true})
	{
		g_report.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		store.load_result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::NotPerformed);
		const auto absent = stores.GetAt(stores.Size() - 1).GetObject();
		Check(absent.GetNamedString(L"store") == L"group_policy_rsop", "Absent RSOP identity lost.");
		Check(absent.GetNamedString(L"status") == L"not_present", "Absent RSOP status incorrect.");
		Check(!absent.HasKey(L"diagnostics"), "Expected RSOP absence produced diagnostics.");
		Check(!absent.HasKey(L"ruleDetails") && !absent.HasKey(L"ruleCount"), "Absent RSOP treated as empty.");
		store.load_result = E_ACCESSDENIED;
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::NotPerformed);
		const auto denied = stores.GetAt(stores.Size() - 1).GetObject();
		Check(denied.GetNamedString(L"status") == L"failed", "RSOP access denial treated as absence.");
		Check(
		    denied.GetNamedArray(L"diagnostics")
		            .GetAt(0)
		            .GetObject()
		            .GetNamedObject(L"error")
		            .GetNamedNumber(L"code") == static_cast<uint32_t>(E_ACCESSDENIED),
		    "RSOP access denial diagnostic lost.");
	}
	FinishProfileJsonReport(0);
	std::printf("Profile and rule-status JSON tests passed.\n");
	return 0;
}
catch (const std::exception& ex)
{
	std::fprintf(stderr, "%s\n", ex.what());
	return 1;
}
