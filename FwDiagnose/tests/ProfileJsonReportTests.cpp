// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "..\ProfileJsonReport.cpp"

#include <fstream>
#include <iterator>
#include <stdexcept>

// NormalizedFirewallRule.cpp, compiled into this test, reads the command-line output flags
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

static void
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
	Check(argc <= 2, "Expected at most one output path.");

	// the output path is optional, so the test can run with no arguments from the solution
	wchar_t temporaryPath[MAX_PATH + 1]{};
	if (argc < 2)
	{
		wchar_t temporaryDirectory[MAX_PATH + 1]{};
		Check(
		    GetTempPathW(ARRAYSIZE(temporaryDirectory), temporaryDirectory) != 0,
		    "Could not find the temp directory.");
		Check(GetTempFileNameW(temporaryDirectory, L"fwd", 0, temporaryPath) != 0, "Could not create a temp file.");
	}
	const auto deleteTemporaryFile = wil::scope_exit(
	    [&]
	    {
		    if (temporaryPath[0] != L'\0')
		    {
			    DeleteFileW(temporaryPath);
		    }
	    });
	PCWSTR const outputPath = argc == 2 ? argv[1] : temporaryPath;

	using namespace winrt::Windows::Data::Json;
	Check(IsShieldsCommand(L"-enable-shields-up:public", L"-enable-shields-up"), "Profile suffix rejected.");
	Check(
	    IsShieldsCommand(L"-disable-shields-up:PRIVATE", L"-disable-shields-up"),
	    "Case insensitive suffix rejected.");
	Check(!IsShieldsCommand(L"-enable-shields-up:invalid", L"-enable-shields-up"), "Invalid suffix accepted.");
	Check(!IsShieldsCommand(L"-enable-shields-up-extra", L"-enable-shields-up"), "Invalid command prefix accepted.");

	const auto unavailable = ReturnJsonCodedValueObject(std::nullopt, PolicyValueKind::Boolean);
	Check(unavailable.GetNamedValue(L"code").ValueType() == JsonValueType::Null, "Unavailable code not null.");
	Check(unavailable.GetNamedString(L"state") == L"unavailable", "Unavailable state incorrect.");
	Check(
	    ReturnJsonCodedValueObject(2, PolicyValueKind::Boolean).GetNamedString(L"state") == L"not_configured",
	    "Not configured lost.");
	Check(
	    ReturnJsonCodedValueObject(999, PolicyValueKind::Action).GetNamedNumber(L"code") == 999,
	    "Unknown raw code lost.");
	JsonObject escaped;
	escaped.SetNamedValue(L"text", String(L"quote\" slash\\ newline\n \u03a9 \u4e2d"));
	const auto formatted = PrettifyJson(escaped);
	Check(
	    JsonObject::Parse(formatted).GetNamedString(L"text") == L"quote\" slash\\ newline\n \u03a9 \u4e2d",
	    "Unicode or escaping failed round trip.");
	Check(
	    PrettifyJson(ReturnJsonCodedValueObject(1, PolicyValueKind::Boolean)) ==
	        L"{ \"code\": 1, \"state\": \"true\" }",
	    "Coded pair not inline.");
	JsonObject category;
	JsonArray ruleDetails;
	ruleDetails.Append(String(L"example-rule"));
	category.SetNamedValue(L"rules", ruleDetails);
	category.SetNamedValue(L"count", JsonValue::CreateNumberValue(1));
	category.SetNamedValue(L"category", String(L"parsing_error"));
	Check(
	    PrettifyJson(category) ==
	        L"{\n  \"category\": \"parsing_error\",\n  \"count\": 1,\n  \"rules\": [\n    \"example-rule\"\n  ]\n}",
	    "Category fields are not in category/count/rules order.");
	category.Remove(L"rules");
	Check(
	    PrettifyJson(category) == L"{\n  \"category\": \"parsing_error\",\n  \"count\": 1\n}",
	    "Nonverbose category fields are not in category/count order.");
	category.SetNamedValue(L"extraField", String(L"preserved"));
	Check(
	    JsonObject::Parse(PrettifyJson(category)).GetNamedString(L"extraField") == L"preserved",
	    "Ordered formatting dropped an additional category field.");
	JsonObject analysis;
	analysis.SetNamedValue(L"categories", JsonArray{});
	analysis.SetNamedValue(L"errorRuleCount", JsonValue::CreateNumberValue(0));
	analysis.SetNamedValue(L"totalRuleCount", JsonValue::CreateNumberValue(733));
	Check(
	    PrettifyJson(analysis) == L"{\n  \"totalRuleCount\": 733,\n  \"errorRuleCount\": 0,\n  \"categories\": []\n}",
	    "Status analysis fields are not in total/error/categories order.");
	analysis.SetNamedValue(L"extraField", String(L"preserved"));
	Check(
	    JsonObject::Parse(PrettifyJson(analysis)).GetNamedString(L"extraField") == L"preserved",
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
	InitializeProfileJsonReport(outputPath, {L"-analyze-rules"});
	WriteFirewallProfileJson(profile, L"analyze_rules");
	const auto output = g_jsonResults.GetAt(0)
	                        .GetObject()
	                        .GetNamedObject(L"data")
	                        .GetNamedArray(L"firewallProfiles")
	                        .GetAt(0)
	                        .GetObject();
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
	const auto collectedOutput = g_jsonResults.GetAt(0)
	                                 .GetObject()
	                                 .GetNamedObject(L"data")
	                                 .GetNamedArray(L"firewallProfiles")
	                                 .GetAt(1)
	                                 .GetObject();
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
	const auto profileText = PrettifyJson(collectedOutput);
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
	    JsonObject::Parse(PrettifyJson(collectedOutput)).GetNamedString(L"extraField") == L"preserved",
	    "Ordered formatting dropped an additional profile field.");
	Check(
	    JsonObject::Parse(PrettifyJson(output)).GetNamedValue(L"profile").ValueType() == JsonValueType::Null,
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
	const auto stores = g_jsonResults.GetAt(0).GetObject().GetNamedObject(L"data").GetNamedArray(L"stores");
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
	const auto storeText = PrettifyJson(normalStore);
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
	g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(true));
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
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
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

	store.store_type = FW_STORE_TYPE_LOCAL;
	store.store_type_string = "Local";
	store.load_result = S_OK;
	ApplicationAnalysis applications;
	applications.applicationRuleCount = 5;
	applications.perUserVariableRuleCount = 1;
	applications.missingApplicationRules.push_back(
	    {L"per-user-rule",
	     L"Per-user rule",
	     L"%LOCALUSERPROFILE%\\app.exe",
	     ApplicationFindingReason::PerUserEnvironmentVariable,
	     S_OK});
	applications.missingApplicationRules.push_back(
	    {L"missing-rule",
	     nullptr,
	     L"C:\\missing\\app.exe",
	     ApplicationFindingReason::FileLookupFailed,
	     HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)});
	applications.serviceProfileVariableRules.push_back(
	    {L"service-rule",
	     L"Service rule",
	     L"%APPDATA%\\app.exe",
	     ApplicationFindingReason::ServiceProfileEnvironmentVariable,
	     S_OK});
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WriteApplicationAnalysisJson(store, applications, L"analyze_rules");
		const auto applicationStore = stores.GetAt(stores.Size() - 1).GetObject();
		const auto section = applicationStore.GetNamedObject(L"applicationAnalysis");
		Check(section.GetNamedString(L"status") == L"completed" && !section.HasKey(L"reason"), "File check status.");
		Check(section.GetNamedNumber(L"applicationRuleCount") == 5, "Application rule count lost.");
		Check(section.GetNamedNumber(L"missingApplicationRuleCount") == 2, "Missing application count lost.");
		Check(section.GetNamedNumber(L"perUserVariableRuleCount") == 1, "Per-user count lost.");
		Check(section.GetNamedNumber(L"serviceProfileVariableRuleCount") == 1, "Service-profile count lost.");
		const auto serviceRule = section.GetNamedArray(L"serviceProfileVariableRules").GetAt(0).GetObject();
		Check(
		    serviceRule.GetNamedString(L"application") == L"%APPDATA%\\app.exe" && !serviceRule.HasKey(L"reason"),
		    "Service-profile rule entry incorrect.");
		Check(section.HasKey(L"missingApplicationRules") == verbose, "Missing rules not limited to verbose output.");

		size_t nextStoreKey = 0;
		const auto applicationStoreText = PrettifyJson(applicationStore);
		for (const auto* key : {L"store", L"displayName", L"ruleDetails", L"applicationAnalysis", L"status"})
		{
			const auto position = applicationStoreText.find(std::wstring(L"\n  \"") + key + L"\":", nextStoreKey);
			Check(position != std::wstring::npos, "Application analysis is not after ruleDetails.");
			nextStoreKey = position + 1;
		}

		size_t nextKey = 0;
		const auto sectionText = PrettifyJson(section);
		for (const auto* key :
		     {L"status",
		      L"applicationRuleCount",
		      L"missingApplicationRuleCount",
		      L"uncheckedApplicationRuleCount",
		      L"perUserVariableRuleCount",
		      L"serviceProfileVariableRuleCount",
		      L"serviceProfileVariableRules",
		      L"uncheckedApplicationRules",
		      L"missingApplicationRules"})
		{
			const auto position = sectionText.find(std::wstring(L"\n  \"") + key + L"\":", nextKey);
			Check(
			    position != std::wstring::npos || (!verbose && std::wstring_view(key) == L"missingApplicationRules"),
			    "Application analysis fields are missing or not in the required order.");
			if (position != std::wstring::npos)
			{
				nextKey = position + 1;
			}
		}
		Check(JsonObject::Parse(sectionText).Size() == section.Size(), "Ordered formatting lost analysis fields.");
		if (verbose)
		{
			const auto missing = section.GetNamedArray(L"missingApplicationRules");
			const auto perUser = missing.GetAt(0).GetObject();
			Check(
			    perUser.GetNamedString(L"reason") == L"per_user_environment_variable" && !perUser.HasKey(L"error"),
			    "Per-user missing rule entry incorrect.");
			const auto lookup = missing.GetAt(1).GetObject();
			Check(lookup.GetNamedValue(L"name").ValueType() == JsonValueType::Null, "Absent rule name not null.");
			Check(lookup.GetNamedString(L"reason") == L"file_lookup_failed", "Lookup failure reason incorrect.");
			Check(
			    lookup.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070003",
			    "Lookup failure error lost.");
			const auto lookupText = PrettifyJson(lookup);
			Check(
			    lookupText.find(L"\"ruleId\"") < lookupText.find(L"\"name\"") &&
			        lookupText.find(L"\"name\"") < lookupText.find(L"\"application\"") &&
			        lookupText.find(L"\"application\"") < lookupText.find(L"\"reason\"") &&
			        lookupText.find(L"\"reason\"") < lookupText.find(L"\"error\""),
			    "Application rule entry fields are not in the required order.");
			Check(
			    lookupText.find(L"\"domain\"") < lookupText.find(L"\"code\"") &&
			        lookupText.find(L"\"code\"") < lookupText.find(L"\"hex\""),
			    "Error fields are not in domain/code/hex order.");
		}
	}
	applications.fileCheck = ApplicationFileCheck::SkippedWow64Redirection;
	WriteApplicationAnalysisJson(store, applications, L"analyze_rules");
	const auto skipped = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"applicationAnalysis");
	Check(
	    skipped.GetNamedString(L"status") == L"skipped" && skipped.GetNamedString(L"reason") == L"wow64_redirection",
	    "WOW64 skip not reported.");
	Check(
	    stores.GetAt(stores.Size() - 2).GetObject().GetNamedObject(L"applicationAnalysis").GetNamedString(L"status") ==
	        L"completed",
	    "Application analysis written to an older store record.");

	// a store with no application rules still has the section, with zero counts and empty lists
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WriteApplicationAnalysisJson(store, ApplicationAnalysis{}, L"analyze_rules");
		const auto empty = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"applicationAnalysis");
		Check(empty.GetNamedString(L"status") == L"completed", "Empty analysis not completed.");
		for (const auto* key :
		     {L"applicationRuleCount",
		      L"missingApplicationRuleCount",
		      L"uncheckedApplicationRuleCount",
		      L"perUserVariableRuleCount",
		      L"serviceProfileVariableRuleCount"})
		{
			Check(empty.GetNamedNumber(key) == 0, "Empty analysis count not zero.");
		}
		Check(empty.GetNamedArray(L"serviceProfileVariableRules").Size() == 0, "Empty warning list not empty.");
		Check(empty.GetNamedArray(L"uncheckedApplicationRules").Size() == 0, "Empty unchecked list not written.");
		Check(
		    verbose ? empty.GetNamedArray(L"missingApplicationRules").Size() == 0
		            : !empty.HasKey(L"missingApplicationRules"),
		    "Empty missing-rule list incorrect for the verbosity.");
		Check(JsonObject::Parse(PrettifyJson(empty)).Size() == empty.Size(), "Empty analysis lost fields.");
	}

	// every string field of a finding can be absent
	ApplicationAnalysis nullFields;
	nullFields.applicationRuleCount = 1;
	nullFields.missingApplicationRules.push_back(
	    {.reason = ApplicationFindingReason::FileLookupFailed, .error = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)});
	WriteApplicationAnalysisJson(store, nullFields, L"analyze_rules");
	const auto nullEntry = stores.GetAt(stores.Size() - 1)
	                           .GetObject()
	                           .GetNamedObject(L"applicationAnalysis")
	                           .GetNamedArray(L"missingApplicationRules")
	                           .GetAt(0)
	                           .GetObject();
	for (const auto* key : {L"ruleId", L"name", L"application"})
	{
		Check(nullEntry.GetNamedValue(key).ValueType() == JsonValueType::Null, "Absent finding field not null.");
	}
	Check(
	    JsonObject::Parse(PrettifyJson(nullEntry)).GetNamedValue(L"ruleId").ValueType() == JsonValueType::Null,
	    "Ordered formatting lost a null rule ID.");
	PackageAnalysis packages;
	packages.packageIdRuleCount = 2;
	packages.packageFamilyNameRuleCount = 3;
	// a rule missing both references appears in both lists
	packages.missingPackageRules.push_back(
	    {L"both-rule", L"Both rule", PackageReference::PackageId, L"S-1-15-2-999", L"both rule"});
	packages.missingPackageRules.push_back(
	    {L"both-rule", L"Both rule", PackageReference::PackageFamilyName, L"Missing.App_x", L"both rule"});
	packages.missingPackageRules.push_back(
	    {L"family-rule", nullptr, PackageReference::PackageFamilyName, L"Missing.App_x", L""});
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WriteApplicationAnalysisJson(store, applications, L"analyze_rules");
		WritePackageAnalysisJson(store, packages, L"analyze_rules");
		const auto packageStore = stores.GetAt(stores.Size() - 1).GetObject();
		const auto section = packageStore.GetNamedObject(L"packageAnalysis");
		Check(section.GetNamedString(L"status") == L"completed", "Package analysis status incorrect.");
		Check(section.GetNamedNumber(L"packageIdRuleCount") == 2, "Package ID rule count lost.");
		Check(section.GetNamedNumber(L"missingPackageIdRuleCount") == 1, "Missing package ID count incorrect.");
		Check(section.GetNamedNumber(L"packageFamilyNameRuleCount") == 3, "Package family name rule count lost.");
		Check(
		    section.GetNamedNumber(L"missingPackageFamilyNameRuleCount") == 2,
		    "Missing package family name count incorrect.");
		Check(!section.HasKey(L"diagnostics"), "Completed package analysis has diagnostics.");
		Check(
		    section.HasKey(L"missingPackageIdRules") == verbose &&
		        section.HasKey(L"missingPackageFamilyNameRules") == verbose,
		    "Missing package rules not limited to verbose output.");

		size_t nextStoreKey = 0;
		const auto packageStoreText = PrettifyJson(packageStore);
		for (const auto* key :
		     {L"store", L"displayName", L"ruleDetails", L"applicationAnalysis", L"packageAnalysis", L"status"})
		{
			const auto position = packageStoreText.find(std::wstring(L"\n  \"") + key + L"\":", nextStoreKey);
			Check(position != std::wstring::npos, "Package analysis is not after applicationAnalysis.");
			nextStoreKey = position + 1;
		}

		size_t nextKey = 0;
		const auto sectionText = PrettifyJson(section);
		for (const auto* key :
		     {L"status",
		      L"packageIdRuleCount",
		      L"missingPackageIdRuleCount",
		      L"packageFamilyNameRuleCount",
		      L"missingPackageFamilyNameRuleCount",
		      L"missingPackageIdRules",
		      L"missingPackageFamilyNameRules"})
		{
			const auto position = sectionText.find(std::wstring(L"\n  \"") + key + L"\":", nextKey);
			Check(
			    position != std::wstring::npos || (!verbose && std::wstring_view(key).starts_with(L"missingPackage") &&
			                                       std::wstring_view(key).ends_with(L"Rules")),
			    "Package analysis fields are missing or not in the required order.");
			if (position != std::wstring::npos)
			{
				nextKey = position + 1;
			}
		}
		Check(JsonObject::Parse(sectionText).Size() == section.Size(), "Ordered formatting lost package fields.");
		if (verbose)
		{
			const auto idRules = section.GetNamedArray(L"missingPackageIdRules");
			Check(idRules.Size() == 1, "Missing package ID list incorrect.");
			const auto idRule = idRules.GetAt(0).GetObject();
			Check(
			    idRule.GetNamedString(L"ruleId") == L"both-rule" && idRule.GetNamedString(L"name") == L"Both rule" &&
			        idRule.GetNamedString(L"packageId") == L"S-1-15-2-999" && idRule.Size() == 3,
			    "Missing package ID entry incorrect.");
			const auto familyRules = section.GetNamedArray(L"missingPackageFamilyNameRules");
			Check(familyRules.Size() == 2, "A rule missing both references is not in both lists.");
			const auto familyRule = familyRules.GetAt(1).GetObject();
			Check(
			    familyRule.GetNamedString(L"ruleId") == L"family-rule" &&
			        familyRule.GetNamedValue(L"name").ValueType() == JsonValueType::Null &&
			        familyRule.GetNamedString(L"packageFamilyName") == L"Missing.App_x" && familyRule.Size() == 3,
			    "Missing package family name entry incorrect.");
			const auto familyText = PrettifyJson(familyRule);
			Check(
			    familyText.find(L"\"ruleId\"") < familyText.find(L"\"name\"") &&
			        familyText.find(L"\"name\"") < familyText.find(L"\"packageFamilyName\""),
			    "Package rule entry fields are not in the required order.");
		}
	}

	// a store with no package rules still has the section, with zero counts and empty lists
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WritePackageAnalysisJson(store, PackageAnalysis{}, L"analyze_rules");
		const auto empty = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"packageAnalysis");
		Check(empty.GetNamedString(L"status") == L"completed", "Empty package analysis not completed.");
		for (const auto* key :
		     {L"packageIdRuleCount",
		      L"missingPackageIdRuleCount",
		      L"packageFamilyNameRuleCount",
		      L"missingPackageFamilyNameRuleCount"})
		{
			Check(empty.GetNamedNumber(key) == 0, "Empty package analysis count not zero.");
		}
		Check(
		    verbose ? empty.GetNamedArray(L"missingPackageIdRules").Size() == 0 &&
		                  empty.GetNamedArray(L"missingPackageFamilyNameRules").Size() == 0
		            : !empty.HasKey(L"missingPackageIdRules") && !empty.HasKey(L"missingPackageFamilyNameRules"),
		    "Empty package lists incorrect for the verbosity.");
	}

	// the installed packages could not be loaded: no counts, one diagnostic with the error
	PackageAnalysis notLoaded;
	notLoaded.packagesLoadResult = E_ACCESSDENIED;
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WritePackageAnalysisJson(store, notLoaded, L"analyze_rules");
	const auto failedPackages = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"packageAnalysis");
	Check(
	    failedPackages.GetNamedString(L"status") == L"failed" && failedPackages.Size() == 2 &&
	        !failedPackages.HasKey(L"packageIdRuleCount"),
	    "Failed package analysis has counts.");
	const auto packageDiagnostic = failedPackages.GetNamedArray(L"diagnostics").GetAt(0).GetObject();
	Check(
	    packageDiagnostic.GetNamedString(L"code") == L"app_packages_not_loaded" &&
	        packageDiagnostic.GetNamedString(L"operation") == L"load_app_packages" &&
	        packageDiagnostic.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070005",
	    "Package load failure diagnostic incorrect.");
	const auto failedText = PrettifyJson(failedPackages);
	Check(failedText.find(L"\"status\"") < failedText.find(L"\"diagnostics\""), "Failed package fields out of order.");

	// every string field of a finding can be absent
	PackageAnalysis nullPackageFields;
	nullPackageFields.packageIdRuleCount = 1;
	nullPackageFields.missingPackageRules.push_back({.reference = PackageReference::PackageId});
	WritePackageAnalysisJson(store, nullPackageFields, L"analyze_rules");
	const auto nullPackageEntry = stores.GetAt(stores.Size() - 1)
	                                  .GetObject()
	                                  .GetNamedObject(L"packageAnalysis")
	                                  .GetNamedArray(L"missingPackageIdRules")
	                                  .GetAt(0)
	                                  .GetObject();
	for (const auto* key : {L"ruleId", L"name", L"packageId"})
	{
		Check(nullPackageEntry.GetNamedValue(key).ValueType() == JsonValueType::Null, "Absent package field not null.");
	}
	// SID-owner analysis: two unresolved owners and two owners without a local profile
	UserOwnerAnalysis owners;
	owners.localProfileCheck = LocalProfileCheck::Completed;
	owners.localUserOwnerRuleCount = 5;
	owners.unresolvedSidRules.push_back(
	    {L"bad-sid-rule",
	     L"Bad SID rule",
	     L"not-a-sid",
	     UserOwnerResolveFailure::InvalidSidString,
	     HRESULT_FROM_WIN32(ERROR_INVALID_SID)});
	owners.unresolvedSidRules.push_back(
	    {L"unknown-rule",
	     nullptr,
	     L"S-1-5-21-1-2-3-1001",
	     UserOwnerResolveFailure::AccountLookupFailed,
	     HRESULT_FROM_WIN32(ERROR_NONE_MAPPED)});
	owners.missingLocalProfileRules.push_back(
	    {L"no-profile-rule", L"No profile rule", L"S-1-5-21-1-2-3-1002", L"CONTOSO", L"alice"});
	owners.missingLocalProfileRules.push_back({L"no-domain-rule", nullptr, L"S-1-5-21-1-2-3-1003", L"", L"bob"});
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WritePackageAnalysisJson(store, PackageAnalysis{}, L"analyze_rules");
		WriteUserOwnerAnalysisJson(store, owners, L"analyze_rules");
		const auto ownerStore = stores.GetAt(stores.Size() - 1).GetObject();
		const auto section = ownerStore.GetNamedObject(L"userOwnerAnalysis");
		Check(
		    section.GetNamedString(L"status") == L"completed" &&
		        section.GetNamedString(L"localProfileCheck") == L"completed" &&
		        section.GetNamedBoolean(L"missingLocalProfileRulesRecreated"),
		    "SID-owner analysis status incorrect.");
		Check(
		    section.GetNamedNumber(L"localUserOwnerRuleCount") == 5 &&
		        section.GetNamedNumber(L"unresolvedSidRuleCount") == 2 &&
		        section.GetNamedNumber(L"missingLocalProfileRuleCount") == 2,
		    "SID-owner analysis counts incorrect.");
		Check(!section.HasKey(L"diagnostics"), "Completed SID-owner analysis has diagnostics.");
		Check(
		    section.HasKey(L"unresolvedSidRules") == verbose && section.HasKey(L"missingLocalProfileRules") == verbose,
		    "SID-owner rule lists not limited to verbose output.");

		size_t nextStoreKey = 0;
		const auto ownerStoreText = PrettifyJson(ownerStore);
		for (const auto* key : {L"store", L"displayName", L"packageAnalysis", L"userOwnerAnalysis", L"status"})
		{
			const auto position = ownerStoreText.find(std::wstring(L"\n  \"") + key + L"\":", nextStoreKey);
			Check(position != std::wstring::npos, "SID-owner analysis is not after packageAnalysis.");
			nextStoreKey = position + 1;
		}

		size_t nextKey = 0;
		const auto sectionText = PrettifyJson(section);
		for (const auto* key :
		     {L"status",
		      L"localUserOwnerRuleCount",
		      L"unresolvedSidRuleCount",
		      L"localProfileCheck",
		      L"missingLocalProfileRulesRecreated",
		      L"missingLocalProfileRuleCount",
		      L"unresolvedSidRules",
		      L"missingLocalProfileRules"})
		{
			const auto position = sectionText.find(std::wstring(L"\n  \"") + key + L"\":", nextKey);
			Check(
			    position != std::wstring::npos || (!verbose && std::wstring_view(key).ends_with(L"Rules")),
			    "SID-owner analysis fields are missing or not in the required order.");
			if (position != std::wstring::npos)
			{
				nextKey = position + 1;
			}
		}
		Check(JsonObject::Parse(sectionText).Size() == section.Size(), "Ordered formatting lost SID-owner fields.");
		if (verbose)
		{
			const auto unresolved = section.GetNamedArray(L"unresolvedSidRules");
			Check(unresolved.Size() == 2, "Unresolved SID list incorrect.");
			const auto invalid = unresolved.GetAt(0).GetObject();
			Check(
			    invalid.GetNamedString(L"ruleId") == L"bad-sid-rule" &&
			        invalid.GetNamedString(L"name") == L"Bad SID rule" &&
			        invalid.GetNamedString(L"localUserOwnerSid") == L"not-a-sid" &&
			        invalid.GetNamedString(L"reason") == L"invalid_sid_string" &&
			        invalid.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070539" && invalid.Size() == 5,
			    "Invalid SID entry incorrect.");
			const auto lookup = unresolved.GetAt(1).GetObject();
			Check(
			    lookup.GetNamedValue(L"name").ValueType() == JsonValueType::Null &&
			        lookup.GetNamedString(L"reason") == L"account_lookup_failed" &&
			        lookup.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070534",
			    "Account lookup failure entry incorrect.");
			const auto lookupText = PrettifyJson(lookup);
			Check(
			    lookupText.find(L"\"ruleId\"") < lookupText.find(L"\"name\"") &&
			        lookupText.find(L"\"name\"") < lookupText.find(L"\"localUserOwnerSid\"") &&
			        lookupText.find(L"\"localUserOwnerSid\"") < lookupText.find(L"\"reason\"") &&
			        lookupText.find(L"\"reason\"") < lookupText.find(L"\"error\""),
			    "Unresolved SID entry fields are not in the required order.");

			const auto missing = section.GetNamedArray(L"missingLocalProfileRules");
			Check(missing.Size() == 2, "Missing local profile list incorrect.");
			const auto withDomain = missing.GetAt(0).GetObject();
			Check(
			    withDomain.GetNamedString(L"ruleId") == L"no-profile-rule" &&
			        withDomain.GetNamedString(L"name") == L"No profile rule" &&
			        withDomain.GetNamedString(L"localUserOwnerSid") == L"S-1-5-21-1-2-3-1002" &&
			        withDomain.GetNamedString(L"domain") == L"CONTOSO" &&
			        withDomain.GetNamedString(L"user") == L"alice" && withDomain.Size() == 5,
			    "Missing local profile entry incorrect.");
			const auto withoutDomain = missing.GetAt(1).GetObject();
			Check(
			    withoutDomain.GetNamedString(L"domain").empty() && withoutDomain.GetNamedString(L"user") == L"bob",
			    "An account without a domain is not an empty domain.");
			const auto missingText = PrettifyJson(withDomain);
			Check(
			    missingText.find(L"\"localUserOwnerSid\"") < missingText.find(L"\"domain\"") &&
			        missingText.find(L"\"domain\"") < missingText.find(L"\"user\""),
			    "Missing local profile entry fields are not in the required order.");
		}
	}

	// a store with no owner rules still has the section; the local-profile check does not apply to it
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WriteUserOwnerAnalysisJson(store, UserOwnerAnalysis{}, L"analyze_rules");
		const auto empty = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"userOwnerAnalysis");
		Check(
		    empty.GetNamedString(L"status") == L"completed" &&
		        empty.GetNamedString(L"localProfileCheck") == L"not_applicable" &&
		        !empty.GetNamedBoolean(L"missingLocalProfileRulesRecreated") &&
		        empty.GetNamedNumber(L"localUserOwnerRuleCount") == 0 &&
		        empty.GetNamedNumber(L"unresolvedSidRuleCount") == 0 && !empty.HasKey(L"missingLocalProfileRuleCount"),
		    "Empty SID-owner analysis incorrect.");
		Check(
		    verbose ? empty.GetNamedArray(L"unresolvedSidRules").Size() == 0 &&
		                  empty.GetNamedArray(L"missingLocalProfileRules").Size() == 0
		            : !empty.HasKey(L"unresolvedSidRules") && !empty.HasKey(L"missingLocalProfileRules"),
		    "Empty SID-owner lists incorrect for the verbosity.");
	}

	// the local profiles could not be read: the unresolved-SID check still ran
	UserOwnerAnalysis profilesNotRead;
	profilesNotRead.localProfileCheck = LocalProfileCheck::Failed;
	profilesNotRead.localProfilesReadResult = E_ACCESSDENIED;
	profilesNotRead.localUserOwnerRuleCount = 3;
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteUserOwnerAnalysisJson(store, profilesNotRead, L"analyze_rules");
	const auto partialOwners = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"userOwnerAnalysis");
	Check(
	    partialOwners.GetNamedString(L"status") == L"partial" &&
	        partialOwners.GetNamedString(L"localProfileCheck") == L"failed" &&
	        partialOwners.GetNamedBoolean(L"missingLocalProfileRulesRecreated") &&
	        partialOwners.GetNamedNumber(L"localUserOwnerRuleCount") == 3 &&
	        !partialOwners.HasKey(L"missingLocalProfileRuleCount"),
	    "Partial SID-owner analysis incorrect.");
	const auto profileDiagnostic = partialOwners.GetNamedArray(L"diagnostics").GetAt(0).GetObject();
	Check(
	    profileDiagnostic.GetNamedString(L"code") == L"local_profiles_not_read" &&
	        profileDiagnostic.GetNamedString(L"operation") == L"read_profile_list" &&
	        profileDiagnostic.GetNamedObject(L"subject").GetNamedString(L"property") == L"localProfiles" &&
	        profileDiagnostic.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070005",
	    "Local profile read failure diagnostic incorrect.");
	const auto partialText = PrettifyJson(partialOwners);
	Check(
	    partialText.find(L"\"localProfileCheck\"") < partialText.find(L"\"unresolvedSidRules\"") &&
	        partialText.find(L"\"missingLocalProfileRules\"") < partialText.find(L"\"diagnostics\""),
	    "Partial SID-owner fields out of order.");

	// every string field of a finding can be absent
	UserOwnerAnalysis nullOwnerFields;
	nullOwnerFields.localProfileCheck = LocalProfileCheck::Completed;
	nullOwnerFields.unresolvedSidRules.push_back({});
	nullOwnerFields.missingLocalProfileRules.push_back({.domain = nullptr, .user = nullptr});
	WriteUserOwnerAnalysisJson(store, nullOwnerFields, L"analyze_rules");
	const auto nullOwners = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"userOwnerAnalysis");
	const auto nullUnresolved = nullOwners.GetNamedArray(L"unresolvedSidRules").GetAt(0).GetObject();
	for (const auto* key : {L"ruleId", L"name", L"localUserOwnerSid"})
	{
		Check(nullUnresolved.GetNamedValue(key).ValueType() == JsonValueType::Null, "Absent SID-owner field not null.");
	}
	const auto nullMissing = nullOwners.GetNamedArray(L"missingLocalProfileRules").GetAt(0).GetObject();
	for (const auto* key : {L"ruleId", L"name", L"localUserOwnerSid", L"domain", L"user"})
	{
		Check(nullMissing.GetNamedValue(key).ValueType() == JsonValueType::Null, "Absent profile field not null.");
	}

	// filter rankings: one rule name shared by two rules (one without an ID), and one single-rule name
	FilterRankings rankings;
	rankings.limit = 3;
	const RankedRuleName shared{
	    .ruleName = L"microsoft edge (mdns-in)",
	    .ruleCount = 2,
	    .filterCount = 396,
	    .filterConditionCount = 1452,
	    .ruleIds = {L"{edge-1}", nullptr}};
	const RankedRuleName single{
	    .ruleName = L"game bar",
	    .ruleCount = 1,
	    .filterCount = 108,
	    .filterConditionCount = 0,
	    .ruleIds = {L"{game}"}};
	rankings.byFilterCount = {shared, single};
	rankings.byFilterConditionCount = {shared};
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WriteUserOwnerAnalysisJson(store, UserOwnerAnalysis{}, L"analyze_rules");
		WriteFilterRankingsJson(store, rankings, L"analyze_rules");
		const auto rankingStore = stores.GetAt(stores.Size() - 1).GetObject();
		const auto section = rankingStore.GetNamedObject(L"filterRankings");
		Check(
		    section.GetNamedString(L"status") == L"completed" &&
		        section.GetNamedString(L"correlationMethod") == L"rule_name" &&
		        section.GetNamedString(L"filterScope") == L"all_wfp_filters" && section.GetNamedNumber(L"limit") == 3 &&
		        !section.HasKey(L"diagnostics"),
		    "Filter ranking fields incorrect.");
		const auto byFilters = section.GetNamedArray(L"byFilterCount");
		const auto byConditions = section.GetNamedArray(L"byFilterConditionCount");
		Check(byFilters.Size() == 2 && byConditions.Size() == 1, "Filter ranking lists incorrect.");
		const auto sharedEntry = byFilters.GetAt(0).GetObject();
		Check(
		    sharedEntry.GetNamedString(L"ruleName") == L"microsoft edge (mdns-in)" &&
		        sharedEntry.GetNamedNumber(L"ruleCount") == 2 && sharedEntry.GetNamedNumber(L"filterCount") == 396 &&
		        sharedEntry.GetNamedNumber(L"filterConditionCount") == 1452 &&
		        sharedEntry.Size() == (verbose ? 5u : 4u),
		    "Ranked rule name entry incorrect.");
		Check(
		    byFilters.GetAt(1).GetObject().GetNamedNumber(L"filterConditionCount") == 0,
		    "A rule name without conditions does not report a zero condition count.");
		Check(sharedEntry.HasKey(L"ruleIds") == verbose, "Ranked rule IDs not limited to verbose output.");
		if (verbose)
		{
			const auto ruleIds = sharedEntry.GetNamedArray(L"ruleIds");
			Check(
			    ruleIds.Size() == 2 && ruleIds.GetAt(0).GetString() == L"{edge-1}" &&
			        ruleIds.GetAt(1).ValueType() == JsonValueType::Null,
			    "Ranked rule IDs incorrect; an absent ID must be null.");
		}

		size_t nextStoreKey = 0;
		const auto rankingStoreText = PrettifyJson(rankingStore);
		for (const auto* key : {L"store", L"displayName", L"userOwnerAnalysis", L"filterRankings", L"status"})
		{
			const auto position = rankingStoreText.find(std::wstring(L"\n  \"") + key + L"\":", nextStoreKey);
			Check(position != std::wstring::npos, "Filter rankings are not after userOwnerAnalysis.");
			nextStoreKey = position + 1;
		}

		size_t nextKey = 0;
		const auto sectionText = PrettifyJson(section);
		for (const auto* key :
		     {L"status", L"correlationMethod", L"filterScope", L"limit", L"byFilterCount", L"byFilterConditionCount"})
		{
			const auto position = sectionText.find(std::wstring(L"\n  \"") + key + L"\":", nextKey);
			Check(position != std::wstring::npos, "Filter ranking fields are missing or not in the required order.");
			nextKey = position + 1;
		}
		Check(
		    JsonObject::Parse(sectionText).Size() == section.Size(),
		    "Ordered formatting lost filter ranking fields.");
		const auto entryText = PrettifyJson(sharedEntry);
		Check(
		    entryText.find(L"\"ruleName\"") < entryText.find(L"\"ruleCount\"") &&
		        entryText.find(L"\"ruleCount\"") < entryText.find(L"\"filterCount\"") &&
		        entryText.find(L"\"filterCount\"") < entryText.find(L"\"filterConditionCount\"") &&
		        (!verbose || entryText.find(L"\"filterConditionCount\"") < entryText.find(L"\"ruleIds\"")),
		    "Ranked rule name fields are not in the required order.");
	}

	// no rule name has filters: the lists are present and empty
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteFilterRankingsJson(store, FilterRankings{.limit = 10}, L"analyze_rules");
	const auto emptyRankings = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"filterRankings");
	Check(
	    emptyRankings.GetNamedString(L"status") == L"completed" && emptyRankings.GetNamedNumber(L"limit") == 10 &&
	        emptyRankings.GetNamedArray(L"byFilterCount").Size() == 0 &&
	        emptyRankings.GetNamedArray(L"byFilterConditionCount").Size() == 0,
	    "Empty filter rankings incorrect.");

	// the WFP filters could not be read: nothing was ranked
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteFilterRankingsJson(store, FilterRankings{.filtersLoadResult = E_ACCESSDENIED, .limit = 3}, L"analyze_rules");
	const auto failedRankings = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"filterRankings");
	Check(
	    failedRankings.GetNamedString(L"status") == L"failed" &&
	        failedRankings.GetNamedString(L"correlationMethod") == L"rule_name" && !failedRankings.HasKey(L"limit") &&
	        !failedRankings.HasKey(L"byFilterCount") && !failedRankings.HasKey(L"byFilterConditionCount"),
	    "Failed filter rankings incorrect.");
	const auto filterDiagnostic = failedRankings.GetNamedArray(L"diagnostics").GetAt(0).GetObject();
	Check(
	    filterDiagnostic.GetNamedString(L"code") == L"wfp_filters_not_loaded" &&
	        filterDiagnostic.GetNamedString(L"operation") == L"enumerate_wfp_filters" &&
	        filterDiagnostic.GetNamedObject(L"subject").GetNamedString(L"property") == L"wfpFilters" &&
	        filterDiagnostic.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070005",
	    "WFP filter read failure diagnostic incorrect.");
	const auto failedRankingText = PrettifyJson(failedRankings);
	Check(
	    failedRankingText.find(L"\"filterScope\"") < failedRankingText.find(L"\"diagnostics\""),
	    "Failed filter ranking fields out of order.");

	// duplicate analysis: a set of two named rules, and a set of two rules with an application but no name
	// or ID; the writer reads only the FW_RULE of each normalized rule
	wchar_t duplicateIdA[] = L"{dup-a}";
	wchar_t duplicateIdB[] = L"{dup-b}";
	wchar_t duplicateNameA[] = L"Alpha";
	wchar_t duplicateNameB[] = L"alpha copy";
	wchar_t duplicateApplication[] = L"%SystemRoot%\\System32\\svchost.exe";
	FW_RULE duplicateFwRules[4]{};
	duplicateFwRules[0].wszRuleId = duplicateIdA;
	duplicateFwRules[0].wszName = duplicateNameA;
	duplicateFwRules[1].wszRuleId = duplicateIdB;
	duplicateFwRules[1].wszName = duplicateNameB;
	duplicateFwRules[2].wszLocalApplication = duplicateApplication;
	duplicateFwRules[3].wszLocalApplication = duplicateApplication;
	std::vector<NormalizedFirewallRule> duplicateRules;
	for (const auto& fwRule : duplicateFwRules)
	{
		duplicateRules.emplace_back(&fwRule, FW_BINARY_VERSION_33);
	}
	DuplicateAnalysis duplicates;
	duplicates.duplicateSets.push_back(
	    {.duplicate_rule_begin = duplicateRules.begin(),
	     .duplicate_rule_end = duplicateRules.begin() + 2,
	     .nameCount = 2});
	duplicates.duplicateSets.push_back(
	    {.duplicate_rule_begin = duplicateRules.begin() + 2,
	     .duplicate_rule_end = duplicateRules.end(),
	     .nameCount = 1});
	duplicates.duplicateRuleCount = 4;
	for (const bool verbose : {false, true})
	{
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WriteFilterRankingsJson(store, FilterRankings{.limit = 10}, L"analyze_rules");
		WriteDuplicateAnalysisJson(store, duplicates, L"analyze_rules");
		const auto duplicateStore = stores.GetAt(stores.Size() - 1).GetObject();
		const auto section = duplicateStore.GetNamedObject(L"duplicateAnalysis");
		const auto ignored = section.GetNamedArray(L"ignoredFields");
		Check(
		    section.GetNamedString(L"status") == L"completed" && ignored.Size() == 4 &&
		        ignored.GetAt(0).GetString() == L"ruleId" && ignored.GetAt(1).GetString() == L"name" &&
		        ignored.GetAt(2).GetString() == L"description" && ignored.GetAt(3).GetString() == L"schemaVersion" &&
		        section.GetNamedNumber(L"duplicateSetCount") == 2 && section.GetNamedNumber(L"duplicateRuleCount") == 4,
		    "Duplicate analysis fields incorrect.");
		Check(section.HasKey(L"duplicateSets") == verbose, "Duplicate sets not limited to verbose output.");
		if (verbose)
		{
			const auto sets = section.GetNamedArray(L"duplicateSets");
			Check(sets.Size() == 2, "Duplicate set count incorrect.");
			const auto named = sets.GetAt(0).GetObject();
			const auto namedRules = named.GetNamedArray(L"rules");
			Check(
			    named.GetNamedNumber(L"ruleCount") == 2 &&
			        named.GetNamedValue(L"application").ValueType() == JsonValueType::Null && namedRules.Size() == 2 &&
			        namedRules.GetAt(0).GetObject().GetNamedString(L"ruleId") == L"{dup-a}" &&
			        namedRules.GetAt(0).GetObject().GetNamedString(L"name") == L"Alpha" &&
			        namedRules.GetAt(1).GetObject().GetNamedString(L"ruleId") == L"{dup-b}" &&
			        namedRules.GetAt(1).GetObject().GetNamedString(L"name") == L"alpha copy",
			    "Named duplicate set incorrect; names must keep their original case.");
			const auto unnamed = sets.GetAt(1).GetObject();
			const auto unnamedRules = unnamed.GetNamedArray(L"rules");
			Check(
			    unnamed.GetNamedNumber(L"ruleCount") == 2 &&
			        unnamed.GetNamedString(L"application") == L"%SystemRoot%\\System32\\svchost.exe" &&
			        unnamedRules.Size() == 2,
			    "Duplicate set with an application incorrect.");
			for (const auto& rule : unnamedRules)
			{
				Check(
				    rule.GetObject().GetNamedValue(L"ruleId").ValueType() == JsonValueType::Null &&
				        rule.GetObject().GetNamedValue(L"name").ValueType() == JsonValueType::Null,
				    "An absent rule ID or name must be null.");
			}
			const auto setText = PrettifyJson(named);
			Check(
			    setText.find(L"\"ruleCount\"") < setText.find(L"\"application\"") &&
			        setText.find(L"\"application\"") < setText.find(L"\"rules\"") &&
			        setText.find(L"\"ruleId\"") < setText.find(L"\"name\""),
			    "Duplicate set fields are not in the required order.");
		}

		size_t nextStoreKey = 0;
		const auto duplicateStoreText = PrettifyJson(duplicateStore);
		for (const auto* key : {L"store", L"filterRankings", L"duplicateAnalysis", L"status"})
		{
			const auto position = duplicateStoreText.find(std::wstring(L"\n  \"") + key + L"\":", nextStoreKey);
			Check(position != std::wstring::npos, "Duplicate analysis is not after filterRankings.");
			nextStoreKey = position + 1;
		}

		size_t nextKey = 0;
		const auto sectionText = PrettifyJson(section);
		for (const auto* key : {L"status", L"ignoredFields", L"duplicateSetCount", L"duplicateRuleCount"})
		{
			const auto position = sectionText.find(std::wstring(L"\n  \"") + key + L"\":", nextKey);
			Check(
			    position != std::wstring::npos,
			    "Duplicate analysis fields are missing or not in the required order.");
			nextKey = position + 1;
		}
		Check(
		    !verbose || sectionText.find(L"\"duplicateRuleCount\"") < sectionText.find(L"\"duplicateSets\""),
		    "Duplicate sets are not after the counts.");
		Check(
		    JsonObject::Parse(sectionText).Size() == section.Size(),
		    "Ordered formatting lost duplicate analysis fields.");
	}

	// no duplicates: the counts are zero and verbose output has an empty list
	WriteFirewallRuleStatusJson(store, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteDuplicateAnalysisJson(store, DuplicateAnalysis{}, L"analyze_rules");
	const auto noDuplicates = stores.GetAt(stores.Size() - 1).GetObject().GetNamedObject(L"duplicateAnalysis");
	Check(
	    noDuplicates.GetNamedString(L"status") == L"completed" &&
	        noDuplicates.GetNamedNumber(L"duplicateSetCount") == 0 &&
	        noDuplicates.GetNamedNumber(L"duplicateRuleCount") == 0 &&
	        noDuplicates.GetNamedArray(L"duplicateSets").Size() == 0,
	    "Empty duplicate analysis incorrect.");
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);

	const auto readReport = [&]()
	{
		std::ifstream file(outputPath, std::ios::binary);
		const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		return JsonObject::Parse(winrt::to_hstring(text));
	};
	const auto readRunStatus = [&]()
	{
		return std::wstring(readReport().GetNamedObject(L"run").GetNamedString(L"status"));
	};
	Check(readRunStatus() == L"partial", "A run whose stores failed or were not collected not reported as partial.");

	InitializeProfileJsonReport(outputPath, {L"-analyze-rules"});
	FinishProfileJsonReport(E_ACCESSDENIED, ReportRunOutcome::RanToEnd);
	Check(readRunStatus() == L"partial", "A recorded failure that did not stop the run was reported as failed.");

	InitializeProfileJsonReport(outputPath, {L"-analyze-rules"});
	FinishProfileJsonReport(E_ACCESSDENIED, ReportRunOutcome::StoppedEarly);
	Check(readRunStatus() == L"failed", "A run that stopped early was not reported as failed.");

	// -clean-rules: one action of each kind, with null and present fields, every outcome, and a keep choice
	// answered and one ended by the input
	const auto keysInOrder = [](const std::wstring& text, std::initializer_list<PCWSTR> keys)
	{
		size_t next = 0;
		for (const auto* key : keys)
		{
			const auto position = text.find(std::wstring(L"\n  \"") + key + L"\":", next);
			if (position == std::wstring::npos)
			{
				return false;
			}
			next = position + 1;
		}
		return true;
	};
	const auto record = [](std::optional<std::wstring> ruleId,
	                       std::optional<std::wstring> name,
	                       DeletionOutcome outcome,
	                       HRESULT error = S_OK)
	{
		return RuleDeletionRecord{
		    .ruleId = std::move(ruleId),
		    .name = std::move(name),
		    .application = L"C:\\missing\\app.exe",
		    .localUserOwnerSid = L"S-1-5-21-1-2-3-1001",
		    .outcome = outcome,
		    .error = error};
	};
	const auto accessDenied = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
	StoreCleanup cleanup;
	cleanup.actions.push_back(
	    {.reason = CleanupReason::MissingApplication,
	     .decision = CleanupDecision::Yes,
	     .approvalSource = ApprovalSource::Prompt,
	     .rules = {record(L"{c1}", L"App rule", DeletionOutcome::Succeeded)}});
	cleanup.actions.push_back(
	    {.reason = CleanupReason::UnresolvedUserOwner,
	     .decision = CleanupDecision::NotPrompted,
	     .approvalSource = ApprovalSource::DeleteAll,
	     .rules = {record(std::nullopt, std::nullopt, DeletionOutcome::Failed, accessDenied)}});
	cleanup.actions.push_back(
	    {.reason = CleanupReason::Duplicate,
	     .decision = CleanupDecision::DeleteAll,
	     .approvalSource = ApprovalSource::Prompt,
	     .rules =
	         {record(L"{d1}", L"Alpha", DeletionOutcome::Succeeded),
	          record(L"{d2}", L"alpha copy", DeletionOutcome::Kept),
	          record(L"{d3}", std::nullopt, DeletionOutcome::Failed, accessDenied)},
	     .keptRuleIndex = 1,
	     .keepChoice = DuplicateKeepRecord{.choices = {L"alpha", L"alpha copy"}, .answer = 2}});
	auto endedKeepChoice = CleanupAction{
	    .reason = CleanupReason::Duplicate,
	    .decision = CleanupDecision::Yes,
	    .approvalSource = ApprovalSource::Prompt,
	    .rules =
	        {record(L"{d4}", L"beta", DeletionOutcome::NotAttempted),
	         record(L"{d5}", L"gamma", DeletionOutcome::NotAttempted)},
	    .keepChoice = DuplicateKeepRecord{.choices = {L"beta", L"gamma"}}};
	for (auto& ruleRecord : endedKeepChoice.rules)
	{
		ruleRecord.application = L"";
	}
	cleanup.actions.push_back(endedKeepChoice);
	cleanup.actions.push_back(
	    {.reason = CleanupReason::Duplicate,
	     .decision = CleanupDecision::No,
	     .rules = {
	         record(L"{d6}", L"delta", DeletionOutcome::NotAttempted),
	         record(L"{d7}", L"delta", DeletionOutcome::NotAttempted)}});
	cleanup.actions.push_back(
	    {.reason = CleanupReason::MissingLocalProfile,
	     .decision = CleanupDecision::No,
	     .rules = {record(L"{c4}", std::nullopt, DeletionOutcome::NotAttempted)}});

	const auto cleanupStores = [&]()
	{
		return g_jsonResults.GetAt(0).GetObject().GetNamedObject(L"data").GetNamedArray(L"stores");
	};
	FirewallPolicyObjects cleanedStore;
	cleanedStore.store_type = FW_STORE_TYPE_LOCAL;
	cleanedStore.store_type_string = "Local";
	cleanedStore.load_result = S_OK;
	std::wstring cleanupText[2];
	for (const bool verbose : {false, true})
	{
		InitializeProfileJsonReport(outputPath, {L"-clean-rules"});
		g_jsonReport.GetNamedObject(L"run").SetNamedValue(L"verbose", JsonValue::CreateBooleanValue(verbose));
		WriteFirewallRuleStatusJson(cleanedStore, 0, {}, L"clean_rules", RuleStatusAnalysis::Performed);
		WriteCleanupJson(cleanedStore, cleanup, L"clean_rules", S_OK);
		cleanupText[verbose] = PrettifyJson(cleanupStores().GetAt(0).GetObject().GetNamedObject(L"cleanup"));
		if (!verbose)
		{
			FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);
		}
	}
	Check(cleanupText[0] == cleanupText[1], "The cleanup section differs with -verbose.");

	const auto cleanedStoreRecord = cleanupStores().GetAt(0).GetObject();
	Check(
	    keysInOrder(PrettifyJson(cleanedStoreRecord), {L"store", L"cleanup", L"status"}),
	    "The cleanup section is not after the analyses and before the store status.");
	const auto section = cleanedStoreRecord.GetNamedObject(L"cleanup");
	Check(
	    section.GetNamedString(L"status") == L"completed" && !section.HasKey(L"diagnostics") &&
	        keysInOrder(cleanupText[0], {L"status", L"counts", L"actions"}) &&
	        JsonObject::Parse(cleanupText[0]).Size() == section.Size(),
	    "Completed cleanup section fields incorrect or out of order.");
	const auto counts = section.GetNamedObject(L"counts");
	Check(
	    counts.GetNamedNumber(L"candidateRuleCount") == 7 && counts.GetNamedNumber(L"attemptedCount") == 4 &&
	        counts.GetNamedNumber(L"succeededCount") == 2 && counts.GetNamedNumber(L"failedCount") == 2 &&
	        counts.GetNamedNumber(L"declinedCount") == 2 && counts.GetNamedNumber(L"skippedCount") == 1,
	    "Cleanup counts incorrect.");
	Check(
	    keysInOrder(
	        PrettifyJson(counts),
	        {L"candidateRuleCount",
	         L"attemptedCount",
	         L"succeededCount",
	         L"failedCount",
	         L"declinedCount",
	         L"skippedCount"}),
	    "Cleanup counts out of order.");

	const auto actions = section.GetNamedArray(L"actions");
	Check(actions.Size() == 6, "One cleanup action per rule or set expected.");
	const auto isNull = [](const JsonObject& object, PCWSTR key)
	{
		return object.HasKey(key) && object.GetNamedValue(key).ValueType() == JsonValueType::Null;
	};
	const auto isAccessDenied = [](const JsonObject& error)
	{
		return error.GetNamedString(L"domain") == L"hresult" && error.GetNamedNumber(L"code") == 2147942405.0 &&
		       error.GetNamedString(L"hex") == L"0x80070005";
	};

	const auto deleted = actions.GetAt(0).GetObject();
	Check(
	    deleted.GetNamedString(L"action") == L"delete_rule" &&
	        deleted.GetNamedString(L"reason") == L"missing_application" &&
	        deleted.GetNamedString(L"ruleId") == L"{c1}" && deleted.GetNamedString(L"name") == L"App rule" &&
	        deleted.GetNamedString(L"application") == L"C:\\missing\\app.exe" &&
	        !deleted.HasKey(L"localUserOwnerSid") && deleted.GetNamedString(L"decision") == L"yes" &&
	        deleted.GetNamedString(L"approvalSource") == L"prompt" &&
	        deleted.GetNamedString(L"outcome") == L"succeeded" && isNull(deleted, L"error") && deleted.Size() == 9,
	    "Deleted missing-application action incorrect.");
	Check(
	    keysInOrder(
	        PrettifyJson(deleted),
	        {L"action",
	         L"reason",
	         L"ruleId",
	         L"name",
	         L"application",
	         L"decision",
	         L"approvalSource",
	         L"outcome",
	         L"error"}),
	    "Single-rule action fields out of order.");

	const auto failed = actions.GetAt(1).GetObject();
	Check(
	    failed.GetNamedString(L"reason") == L"unresolved_user_owner" && isNull(failed, L"ruleId") &&
	        isNull(failed, L"name") && failed.GetNamedString(L"localUserOwnerSid") == L"S-1-5-21-1-2-3-1001" &&
	        !failed.HasKey(L"application") && failed.GetNamedString(L"decision") == L"not_prompted" &&
	        failed.GetNamedString(L"approvalSource") == L"delete_all" &&
	        failed.GetNamedString(L"outcome") == L"failed" && isAccessDenied(failed.GetNamedObject(L"error")),
	    "Failed unresolved-owner action incorrect; a missing rule ID or name must be null.");
	Check(
	    keysInOrder(PrettifyJson(failed), {L"ruleId", L"name", L"localUserOwnerSid", L"decision"}),
	    "The owner SID is not where the application would be.");

	const auto partial = actions.GetAt(2).GetObject();
	const auto keepChoice = partial.GetNamedObject(L"keepChoice");
	const auto choices = keepChoice.GetNamedArray(L"choices");
	const auto keptRule = partial.GetNamedObject(L"keptRule");
	Check(
	    partial.GetNamedString(L"action") == L"delete_duplicates" &&
	        partial.GetNamedString(L"reason") == L"duplicate" && partial.GetNamedNumber(L"ruleCount") == 3 &&
	        partial.GetNamedString(L"application") == L"C:\\missing\\app.exe" && !partial.HasKey(L"ruleId") &&
	        partial.GetNamedString(L"decision") == L"delete_all" &&
	        partial.GetNamedString(L"approvalSource") == L"prompt" && choices.Size() == 2 &&
	        choices.GetAt(0).GetString() == L"alpha" && choices.GetAt(1).GetString() == L"alpha copy" &&
	        keepChoice.GetNamedString(L"result") == L"chosen" && keepChoice.GetNamedNumber(L"answer") == 2 &&
	        keptRule.GetNamedString(L"ruleId") == L"{d2}" && keptRule.GetNamedString(L"name") == L"alpha copy" &&
	        partial.GetNamedString(L"outcome") == L"partial",
	    "Partly deleted duplicate action incorrect.");
	const auto partialRules = partial.GetNamedArray(L"rules");
	Check(
	    partialRules.Size() == 3 && partialRules.GetAt(0).GetObject().GetNamedString(L"outcome") == L"succeeded" &&
	        isNull(partialRules.GetAt(0).GetObject(), L"error") &&
	        partialRules.GetAt(1).GetObject().GetNamedString(L"outcome") == L"kept" &&
	        isNull(partialRules.GetAt(1).GetObject(), L"error") &&
	        partialRules.GetAt(2).GetObject().GetNamedString(L"outcome") == L"failed" &&
	        isNull(partialRules.GetAt(2).GetObject(), L"name") &&
	        isAccessDenied(partialRules.GetAt(2).GetObject().GetNamedObject(L"error")),
	    "Duplicate rule outcomes incorrect; only the failed rule has an error.");
	Check(
	    keysInOrder(
	        PrettifyJson(partial),
	        {L"action",
	         L"reason",
	         L"ruleCount",
	         L"application",
	         L"decision",
	         L"approvalSource",
	         L"keepChoice",
	         L"keptRule",
	         L"outcome",
	         L"rules"}) &&
	        keysInOrder(PrettifyJson(keepChoice), {L"choices", L"result", L"answer"}) &&
	        keysInOrder(PrettifyJson(keptRule), {L"ruleId", L"name"}) &&
	        keysInOrder(PrettifyJson(partialRules.GetAt(2).GetObject()), {L"ruleId", L"name", L"outcome", L"error"}),
	    "Duplicate action fields out of order.");

	const auto ended = actions.GetAt(3).GetObject();
	const auto endedChoice = ended.GetNamedObject(L"keepChoice");
	Check(
	    endedChoice.GetNamedString(L"result") == L"end_of_input" && isNull(endedChoice, L"answer") &&
	        endedChoice.GetNamedArray(L"choices").Size() == 2 && isNull(ended, L"keptRule") &&
	        isNull(ended, L"application") && ended.GetNamedString(L"outcome") == L"not_attempted",
	    "A keep choice ended by the input must have a null answer and no kept rule.");

	const auto declined = actions.GetAt(4).GetObject();
	Check(
	    declined.GetNamedString(L"decision") == L"no" && isNull(declined, L"approvalSource") &&
	        isNull(declined, L"keepChoice") && isNull(declined, L"keptRule") &&
	        declined.GetNamedString(L"outcome") == L"not_attempted",
	    "A declined set must have null keepChoice, keptRule, and approvalSource.");
	const auto noProfile = actions.GetAt(5).GetObject();
	Check(
	    noProfile.GetNamedString(L"reason") == L"missing_local_profile" &&
	        noProfile.GetNamedString(L"localUserOwnerSid") == L"S-1-5-21-1-2-3-1001" &&
	        noProfile.GetNamedString(L"decision") == L"no",
	    "Missing-local-profile action incorrect.");

	Check(
	    g_jsonResults.GetAt(0).GetObject().GetNamedArray(L"diagnostics").Size() == 0,
	    "-clean-rules is fully exported, so its result must have no json_export_incomplete diagnostic.");

	// cleanupSummary across stores: the cleaned store above, a store interrupted after one deletion, a store
	// with nothing to clean, a store skipped because it cannot be modified locally, and one not skipped
	FW_RULE skippedFwRule{};
	FirewallPolicyObjects interruptedStore;
	interruptedStore.store_type = FW_STORE_TYPE_GPO;
	interruptedStore.store_type_string = "Group Policy";
	interruptedStore.load_result = S_OK;
	FirewallPolicyObjects emptyStore;
	emptyStore.store_type = FW_STORE_TYPE_MDM;
	emptyStore.store_type_string = "MDM";
	emptyStore.load_result = S_OK;
	FirewallPolicyObjects skippedStore;
	skippedStore.store_type = FW_STORE_TYPE_GP_RSOP;
	skippedStore.store_type_string = "Group Policy (RSOP)";
	skippedStore.load_result = S_OK;
	skippedStore.normalizedRules.emplace_back(&skippedFwRule, FW_BINARY_VERSION_33);
	FirewallPolicyObjects emptyUnmodifiableStore;
	emptyUnmodifiableStore.store_type = FW_STORE_TYPE_WSH_STATIC;
	emptyUnmodifiableStore.store_type_string = "Service Hardening (static)";
	emptyUnmodifiableStore.load_result = S_OK;

	StoreCleanup interrupted;
	interrupted.actions.push_back(cleanup.actions[0]);
	WriteFirewallRuleStatusJson(interruptedStore, 0, {}, L"clean_rules", RuleStatusAnalysis::Performed);
	WriteCleanupJson(interruptedStore, interrupted, L"clean_rules", E_ACCESSDENIED);
	WriteFirewallRuleStatusJson(emptyStore, 0, {}, L"clean_rules", RuleStatusAnalysis::Performed);
	WriteCleanupJson(emptyStore, StoreCleanup{}, L"clean_rules", S_OK);
	WriteFirewallRuleStatusJson(skippedStore, 0, {}, L"clean_rules", RuleStatusAnalysis::NotPerformed);
	WriteCleanupSkippedStoreJson(skippedStore, L"clean_rules");
	WriteFirewallRuleStatusJson(emptyUnmodifiableStore, 0, {}, L"clean_rules", RuleStatusAnalysis::NotPerformed);
	WriteCleanupSkippedStoreJson(emptyUnmodifiableStore, L"clean_rules");

	const auto interruptedSection = cleanupStores().GetAt(1).GetObject().GetNamedObject(L"cleanup");
	const auto interruptedDiagnostics = interruptedSection.GetNamedArray(L"diagnostics");
	Check(
	    interruptedSection.GetNamedString(L"status") == L"partial" && interruptedDiagnostics.Size() == 1 &&
	        interruptedSection.GetNamedArray(L"actions").Size() == 1 &&
	        keysInOrder(PrettifyJson(interruptedSection), {L"status", L"counts", L"actions", L"diagnostics"}),
	    "An interrupted cleanup must be partial with one diagnostic after its actions.");
	const auto interruption = interruptedDiagnostics.GetAt(0).GetObject();
	Check(
	    interruption.GetNamedString(L"code") == L"cleanup_interrupted" &&
	        interruption.GetNamedString(L"severity") == L"error" &&
	        interruption.GetNamedString(L"operation") == L"clean_rules" &&
	        interruption.GetNamedObject(L"subject").GetNamedString(L"property") == L"cleanup" &&
	        interruption.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070005",
	    "The cleanup_interrupted diagnostic is incorrect.");

	const auto emptySection = cleanupStores().GetAt(2).GetObject().GetNamedObject(L"cleanup");
	const auto emptyCounts = emptySection.GetNamedObject(L"counts");
	bool allZero = emptyCounts.Size() == 6;
	for (const auto* key :
	     {L"candidateRuleCount",
	      L"attemptedCount",
	      L"succeededCount",
	      L"failedCount",
	      L"declinedCount",
	      L"skippedCount"})
	{
		allZero = allZero && emptyCounts.GetNamedNumber(key) == 0;
	}
	Check(
	    emptySection.GetNamedString(L"status") == L"completed" && emptySection.GetNamedArray(L"actions").Size() == 0 &&
	        allZero,
	    "A store with nothing to clean must have no actions and zero counts.");
	Check(
	    cleanupStores().GetAt(3).GetObject().GetNamedString(L"status") == L"skipped" &&
	        !cleanupStores().GetAt(3).GetObject().HasKey(L"cleanup") &&
	        cleanupStores().GetAt(4).GetObject().GetNamedString(L"status") == L"completed",
	    "Store statuses for the skipped-store test incorrect.");

	const auto data = g_jsonResults.GetAt(0).GetObject().GetNamedObject(L"data");
	const auto summary = data.GetNamedObject(L"cleanupSummary");
	const auto totals = summary.GetNamedObject(L"counts");
	Check(
	    summary.GetNamedNumber(L"cleanedStoreCount") == 3 && totals.GetNamedNumber(L"candidateRuleCount") == 8 &&
	        totals.GetNamedNumber(L"attemptedCount") == 5 && totals.GetNamedNumber(L"succeededCount") == 3 &&
	        totals.GetNamedNumber(L"failedCount") == 2 && totals.GetNamedNumber(L"declinedCount") == 2 &&
	        totals.GetNamedNumber(L"skippedCount") == 1,
	    "cleanupSummary totals do not add the cleaned stores' counts.");
	const auto skippedStores = summary.GetNamedArray(L"skippedStores");
	Check(
	    skippedStores.Size() == 1 &&
	        skippedStores.GetAt(0).GetObject().GetNamedString(L"store") == L"group_policy_rsop" &&
	        skippedStores.GetAt(0).GetObject().GetNamedString(L"reason") == L"store_cannot_be_modified_locally" &&
	        keysInOrder(PrettifyJson(skippedStores.GetAt(0).GetObject()), {L"store", L"reason"}),
	    "skippedStores must list only stores whose status is skipped.");
	const auto summaryText = PrettifyJson(summary);
	Check(
	    keysInOrder(summaryText, {L"cleanedStoreCount", L"counts", L"skippedStores"}) &&
	        JsonObject::Parse(summaryText).Size() == summary.Size(),
	    "cleanupSummary fields out of order.");
	Check(
	    keysInOrder(PrettifyJson(data), {L"firewallProfiles", L"stores", L"cleanupSummary"}),
	    "cleanupSummary is not after the stores.");
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);
	Check(
	    readReport().GetNamedArray(L"results").GetAt(0).GetObject().GetNamedString(L"status") == L"partial",
	    "A -clean-rules result with an interrupted cleanup is not partial.");

	// result and run status: a result is completed only when everything it reports finished
	FirewallProfileData completedProfile;
	completedProfile.name = L"Public";
	FirewallPolicyObjects statusStore;
	statusStore.store_type = FW_STORE_TYPE_LOCAL;
	statusStore.store_type_string = "Local";
	statusStore.load_result = S_OK;
	FirewallPolicyObjects absentRsop;
	absentRsop.store_type = FW_STORE_TYPE_GP_RSOP;
	absentRsop.store_type_string = "Group Policy (RSOP)";
	absentRsop.load_result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	FirewallPolicyObjects gpoStatusStore;
	gpoStatusStore.store_type = FW_STORE_TYPE_GPO;
	gpoStatusStore.store_type_string = "Group Policy";
	gpoStatusStore.load_result = S_OK;
	FW_RULE statusSkippedFwRule{};
	FirewallPolicyObjects skippedStatusStore;
	skippedStatusStore.store_type = FW_STORE_TYPE_GP_RSOP;
	skippedStatusStore.store_type_string = "Group Policy (RSOP)";
	skippedStatusStore.load_result = S_OK;
	skippedStatusStore.normalizedRules.emplace_back(&statusSkippedFwRule, FW_BINARY_VERSION_33);
	// a profile, a completed store with every analysis, and an RSOP store that is not present
	const auto writeCompletedResult = [&](PCWSTR command)
	{
		WriteFirewallProfileJson(completedProfile, command);
		WriteFirewallRuleStatusJson(statusStore, 0, {}, command, RuleStatusAnalysis::Performed);
		WriteApplicationAnalysisJson(statusStore, ApplicationAnalysis{}, command);
		WritePackageAnalysisJson(statusStore, PackageAnalysis{}, command);
		WriteUserOwnerAnalysisJson(statusStore, UserOwnerAnalysis{}, command);
		WriteFilterRankingsJson(statusStore, FilterRankings{.limit = 10}, command);
		WriteDuplicateAnalysisJson(statusStore, DuplicateAnalysis{}, command);
		WriteFirewallRuleStatusJson(absentRsop, 0, {}, command, RuleStatusAnalysis::Performed);
	};
	// runs a report and returns the first result's status and the run's status
	const auto reportStatus = [&](const std::vector<PCWSTR>& arguments,
	                              const auto& write,
	                              int exitCode = 0,
	                              ReportRunOutcome outcome = ReportRunOutcome::RanToEnd)
	{
		InitializeProfileJsonReport(outputPath, arguments);
		write();
		FinishProfileJsonReport(exitCode, outcome);
		const auto report = readReport();
		return std::pair{
		    std::wstring(report.GetNamedArray(L"results").GetAt(0).GetObject().GetNamedString(L"status")),
		    std::wstring(report.GetNamedObject(L"run").GetNamedString(L"status"))};
	};
	using StatusPair = std::pair<std::wstring, std::wstring>;
	const StatusPair allCompleted{L"completed", L"completed"};
	const StatusPair resultPartial{L"partial", L"partial"};
	const StatusPair runPartial{L"completed", L"partial"};
	const auto analyzeCompleted = [&]()
	{
		writeCompletedResult(L"analyze_rules");
	};
	Check(
	    reportStatus({L"-analyze-rules"}, analyzeCompleted) == allCompleted,
	    "A fully exported -analyze-rules run is not completed.");
	Check(
	    readReport().GetNamedArray(L"results").GetAt(0).GetObject().GetNamedArray(L"diagnostics").Size() == 0,
	    "An -analyze-rules result has a diagnostic.");
	Check(
	    reportStatus(
	        {L"-clean-rules"},
	        [&]()
	        {
		        writeCompletedResult(L"clean_rules");
		        WriteCleanupJson(statusStore, StoreCleanup{}, L"clean_rules", S_OK);
	        }) == allCompleted,
	    "A fully exported -clean-rules run is not completed.");
	Check(
	    readReport().GetNamedArray(L"results").GetAt(0).GetObject().GetNamedArray(L"diagnostics").Size() == 0,
	    "A -clean-rules result has a diagnostic.");
	Check(
	    reportStatus({L"-analyze-rules"}, analyzeCompleted, 1) == runPartial,
	    "A nonzero exit code must make only the run partial.");
	Check(
	    reportStatus({L"-analyze-rules"}, analyzeCompleted, 1, ReportRunOutcome::StoppedEarly) ==
	        StatusPair{L"completed", L"failed"},
	    "A run that stopped early must be failed.");
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        WriteFirewallRuleStatusJson(
		            skippedStatusStore,
		            0,
		            {},
		            L"analyze_rules",
		            RuleStatusAnalysis::NotPerformed);
	        }) == allCompleted,
	    "A skipped store must not make the result partial.");
	for (const auto loadResult : {E_ACCESSDENIED, E_PENDING, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)})
	{
		Check(
		    reportStatus(
		        {L"-analyze-rules"},
		        [&]()
		        {
			        analyzeCompleted();
			        gpoStatusStore.load_result = loadResult;
			        WriteFirewallRuleStatusJson(gpoStatusStore, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
			        gpoStatusStore.load_result = S_OK;
		        }) == resultPartial,
		    "A failed, not-collected, or not-present store with an error must make the result partial.");
	}
	for (const auto* severity : {L"error", L"warning"})
	{
		Check(
		    reportStatus(
		        {L"-analyze-rules"},
		        [&]()
		        {
			        analyzeCompleted();
			        auto diagnostic = ReturnJsonDiagnosticObject(L"rules", L"test", E_FAIL, L"Test diagnostic.");
			        diagnostic.SetNamedValue(L"severity", String(severity));
			        FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_LOCAL)
			            .GetNamedArray(L"diagnostics")
			            .Append(diagnostic);
		        }) == (std::wstring_view(severity) == L"error" ? resultPartial : allCompleted),
		    "Only an error diagnostic on a store may make the result partial.");
	}
	ApplicationAnalysis uncheckedApplications;
	uncheckedApplications.applicationRuleCount = 1;
	uncheckedApplications.uncheckedApplicationRules.push_back(
	    {.ruleId = L"unchecked-rule",
	     .name = L"Unchecked rule",
	     .application = L"%TEST%\\app.exe",
	     .reason = ApplicationFindingReason::EnvironmentExpansionFailed,
	     .error = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY)});
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        WriteApplicationAnalysisJson(statusStore, uncheckedApplications, L"analyze_rules");
	        }) == resultPartial,
	    "A partial store section must make the result partial.");
	PackageAnalysis packagesNotLoaded;
	packagesNotLoaded.packagesLoadResult = E_ACCESSDENIED;
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        WritePackageAnalysisJson(statusStore, packagesNotLoaded, L"analyze_rules");
	        }) == resultPartial,
	    "A failed store section must make the result partial.");
	const AppContainerSidFailure familySidFailure{L"Bad.Family_x", PackageNameKind::FamilyName, E_INVALIDARG};
	const AppContainerSidFailure fullSidFailure{L"Bad.Full_1.0.0.0_x64__x", PackageNameKind::FullName, E_INVALIDARG};
	for (const auto& sidFailure : {familySidFailure, fullSidFailure})
	{
		PackageAnalysis withSidFailure;
		withSidFailure.sidFailures = {sidFailure};
		Check(
		    reportStatus(
		        {L"-analyze-rules"},
		        [&]()
		        {
			        analyzeCompleted();
			        WritePackageAnalysisJson(statusStore, withSidFailure, L"analyze_rules");
		        }) == (sidFailure.kind == PackageNameKind::FamilyName ? resultPartial : allCompleted),
		    "Only a family-name SID failure may make the result partial.");
	}
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        WriteStoreInterruptedJson(statusStore, L"analyze_rules", L"analyze_duplicates", E_OUTOFMEMORY, nullptr);
	        }) == resultPartial,
	    "An interrupted store must make the result partial.");
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        WriteFirewallProfileJson(profile, L"analyze_rules");
	        }) == resultPartial,
	    "A profile with diagnostics must make the result partial.");
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        RecordProfileJsonFailure(L"analyze_rules", E_ACCESSDENIED, "Profiles could not be read.");
	        }) == StatusPair{L"failed", L"partial"},
	    "A result RecordProfileJsonFailure marked failed must stay failed.");
	Check(
	    reportStatus(
	        {L"-analyze-rules"},
	        [&]()
	        {
		        analyzeCompleted();
		        RecordProfileJsonFailure(nullptr, E_ACCESSDENIED, "Profiles could not be read.");
	        }) == runPartial,
	    "A report diagnostic must keep the run from being completed.");

	// a Shields Up change exports only the profiles, so its result is partial with a warning
	InitializeProfileJsonReport(outputPath, {L"-analyze-rules", L"-enable-shields-up:public"});
	Check(ProfileJsonReportHasIncompleteCommand(), "A Shields Up change is not reported as incomplete.");
	analyzeCompleted();
	WriteFirewallProfileJson(completedProfile, L"shields_up_change");
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);
	Check(!ProfileJsonReportHasIncompleteCommand(), "An incomplete command reported after the report finished.");
	const auto shieldsReport = readReport();
	const auto shieldsResults = shieldsReport.GetNamedArray(L"results");
	Check(shieldsResults.Size() == 2, "One result per command expected.");
	const auto shieldsResult = shieldsResults.GetAt(1).GetObject();
	const auto shieldsDiagnostics = shieldsResult.GetNamedArray(L"diagnostics");
	Check(
	    shieldsResult.GetNamedString(L"command") == L"shields_up_change" &&
	        shieldsResult.GetNamedString(L"status") == L"partial" && shieldsDiagnostics.Size() == 1 &&
	        shieldsDiagnostics.GetAt(0).GetObject().GetNamedString(L"code") == L"json_export_incomplete" &&
	        shieldsDiagnostics.GetAt(0).GetObject().GetNamedString(L"severity") == L"warning" &&
	        shieldsDiagnostics.GetAt(0).GetObject().GetNamedString(L"message") ==
	            L"Only the firewall-profile configuration is exported for a Shields Up change. The change itself is "
	            L"not yet exported.",
	    "The Shields Up result must be partial with a json_export_incomplete warning.");
	Check(
	    shieldsResults.GetAt(0).GetObject().GetNamedString(L"status") == L"completed" &&
	        shieldsReport.GetNamedObject(L"run").GetNamedString(L"status") == L"partial",
	    "A Shields Up change must make only its own result and the run partial.");
	InitializeProfileJsonReport(outputPath, {L"-analyze-rules", L"-verbose"});
	Check(!ProfileJsonReportHasIncompleteCommand(), "-analyze-rules reported as incomplete.");
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);

	// an error that stopped a store's analysis
	const std::wstring interruptedMessage =
	    L"An error stopped the analysis of this store; the sections written before it are kept.";
	InitializeProfileJsonReport(outputPath, {L"-analyze-rules"});
	WriteFirewallRuleStatusJson(statusStore, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteApplicationAnalysisJson(statusStore, ApplicationAnalysis{}, L"analyze_rules");
	WriteStoreInterruptedJson(statusStore, L"analyze_rules", L"analyze_packages", E_OUTOFMEMORY, "bad allocation");
	const auto interruptedLocal = FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_LOCAL);
	const auto interruptedLocalDiagnostics = interruptedLocal.GetNamedArray(L"diagnostics");
	Check(
	    interruptedLocal.GetNamedString(L"status") == L"partial" && interruptedLocal.HasKey(L"applicationAnalysis") &&
	        interruptedLocalDiagnostics.Size() == 1,
	    "An interrupted store must be partial and keep the sections written before the error.");
	const auto storeInterruption = interruptedLocalDiagnostics.GetAt(0).GetObject();
	Check(
	    storeInterruption.GetNamedString(L"code") == L"store_analysis_interrupted" &&
	        storeInterruption.GetNamedString(L"severity") == L"error" &&
	        storeInterruption.GetNamedString(L"operation") == L"analyze_packages" &&
	        storeInterruption.GetNamedObject(L"subject").GetNamedString(L"property") == L"store" &&
	        storeInterruption.GetNamedObject(L"subject").GetNamedString(L"store") == L"local" &&
	        storeInterruption.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x8007000E" &&
	        storeInterruption.GetNamedString(L"message") == interruptedMessage + L" bad allocation",
	    "The store_analysis_interrupted diagnostic is incorrect.");
	WriteStoreInterruptedJson(gpoStatusStore, L"analyze_rules", L"load_firewall_rules", E_FAIL, nullptr);
	const auto interruptedGpo = FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_GPO);
	Check(
	    interruptedGpo && interruptedGpo.GetNamedString(L"store") == L"group_policy" &&
	        interruptedGpo.GetNamedString(L"displayName") == L"Group Policy" &&
	        interruptedGpo.GetNamedString(L"status") == L"failed" &&
	        interruptedGpo.GetNamedArray(L"diagnostics").Size() == 1 &&
	        interruptedGpo.GetNamedArray(L"diagnostics").GetAt(0).GetObject().GetNamedString(L"message") ==
	            interruptedMessage,
	    "A store interrupted before its record was written must get a failed record.");
	WriteStoreInterruptedJson(gpoStatusStore, L"analyze_rules", L"load_firewall_rules", E_FAIL, nullptr);
	Check(
	    interruptedGpo.GetNamedString(L"status") == L"failed" &&
	        interruptedGpo.GetNamedArray(L"diagnostics").Size() == 2 &&
	        ReturnJsonResultObject(L"analyze_rules").GetNamedObject(L"data").GetNamedArray(L"stores").Size() == 2,
	    "A second interruption must add a diagnostic to the same failed record.");
	WriteFirewallRuleStatusJson(absentRsop, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteStoreInterruptedJson(absentRsop, L"analyze_rules", L"analyze_rules", E_FAIL, nullptr);
	const auto interruptedRsop = FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_GP_RSOP);
	Check(
	    interruptedRsop.GetNamedString(L"status") == L"not_present" &&
	        interruptedRsop.GetNamedArray(L"diagnostics").Size() == 1,
	    "A store record without diagnostics must get a diagnostics array.");
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);
	const auto interruptedReport = readReport();
	Check(
	    interruptedReport.GetNamedArray(L"results").GetAt(0).GetObject().GetNamedString(L"status") == L"partial" &&
	        interruptedReport.GetNamedObject(L"run").GetNamedString(L"status") == L"partial",
	    "A report with an interrupted store must be partial.");
	WriteStoreInterruptedJson(statusStore, L"analyze_rules", L"analyze_packages", E_FAIL, nullptr);
	Check(!ProfileJsonReportEnabled(), "Writing an interruption after the report finished enabled the report.");

	// the package identity is added to every rule entry
	const RulePackageIdentity fromRuleIdentity{
	    .packageId = L"S-1-15-2-1",
	    .packageIdSource = PackageIdSource::Rule,
	    .packageFamilyName = L"Contoso.App_8wekyb3d8bbwe"};
	const RulePackageIdentity derivedIdentity{
	    .packageId = L"S-1-15-2-2",
	    .packageIdSource = PackageIdSource::DerivedFromFamilyName,
	    .packageFamilyName = L"Derived.App_x"};
	const RulePackageIdentity notDerivedIdentity{
	    .packageId = std::nullopt,
	    .packageIdSource = PackageIdSource::DerivedFromFamilyName,
	    .packageFamilyName = L"Not.Derived_x",
	    .packageIdError = E_INVALIDARG};
	const RulePackageIdentity idOnlyIdentity{.packageId = L"S-1-15-2-3", .packageFamilyName = std::nullopt};
	const auto optionalStringIs = [&](const JsonObject& entry, PCWSTR key, const std::optional<std::wstring>& value)
	{
		return value.has_value() ? entry.HasKey(key) && std::wstring_view(entry.GetNamedString(key)) == *value
		                         : isNull(entry, key);
	};
	const auto hasIdentity = [&](const JsonObject& entry, const std::optional<RulePackageIdentity>& identity)
	{
		if (!identity.has_value())
		{
			return !entry.HasKey(L"packageId") && !entry.HasKey(L"packageIdSource") &&
			       !entry.HasKey(L"packageIdError") && !entry.HasKey(L"packageFamilyName");
		}
		return optionalStringIs(entry, L"packageId", identity->packageId) &&
		       entry.GetNamedString(L"packageIdSource") ==
		           (identity->packageIdSource == PackageIdSource::Rule ? L"rule" : L"derived_from_family_name") &&
		       (FAILED(identity->packageIdError) ? entry.GetNamedObject(L"packageIdError").GetNamedNumber(L"code") ==
		                                               static_cast<uint32_t>(identity->packageIdError)
		                                         : !entry.HasKey(L"packageIdError")) &&
		       optionalStringIs(entry, L"packageFamilyName", identity->packageFamilyName);
	};

	FW_RULE identityFwRules[3]{};
	wchar_t identityRuleIds[3][8]{L"{id-0}", L"{id-1}", L"{id-2}"};
	std::vector<NormalizedFirewallRule> identityRules;
	for (size_t index = 0; index < ARRAYSIZE(identityFwRules); ++index)
	{
		identityFwRules[index].wszRuleId = identityRuleIds[index];
		identityRules.emplace_back(&identityFwRules[index], FW_BINARY_VERSION_33);
	}
	identityRules[0].package_identity = derivedIdentity;
	identityRules[1].package_identity = fromRuleIdentity;
	RuleStatusCategories identityCategories;
	identityCategories.partiallyIgnored.rules = {&identityRules[0], &identityRules[2]};
	FirewallPolicyObjects identityStore;
	identityStore.store_type = FW_STORE_TYPE_LOCAL;
	identityStore.store_type_string = "Local";
	identityStore.load_result = S_OK;

	ApplicationAnalysis identityApplications;
	identityApplications.applicationRuleCount = 4;
	identityApplications.serviceProfileVariableRules.push_back(
	    {.ruleId = L"service-rule",
	     .application = L"%APPDATA%\\app.exe",
	     .reason = ApplicationFindingReason::ServiceProfileEnvironmentVariable,
	     .packageIdentity = fromRuleIdentity});
	identityApplications.uncheckedApplicationRules.push_back(
	    {.ruleId = L"unchecked-rule",
	     .application = L"%TEST%\\app.exe",
	     .reason = ApplicationFindingReason::EnvironmentExpansionFailed,
	     .error = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY),
	     .packageIdentity = derivedIdentity});
	identityApplications.missingApplicationRules.push_back(
	    {.ruleId = L"missing-rule",
	     .name = L"Missing rule",
	     .application = L"C:\\missing\\app.exe",
	     .reason = ApplicationFindingReason::FileLookupFailed,
	     .error = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND),
	     .packageIdentity = notDerivedIdentity});
	identityApplications.missingApplicationRules.push_back(
	    {.ruleId = L"no-package-rule",
	     .application = L"C:\\missing\\other.exe",
	     .reason = ApplicationFindingReason::FileLookupFailed,
	     .error = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)});
	PackageAnalysis identityPackages;
	identityPackages.packageIdRuleCount = 1;
	identityPackages.packageFamilyNameRuleCount = 1;
	identityPackages.missingPackageRules.push_back(
	    {.ruleId = L"id-rule",
	     .reference = PackageReference::PackageId,
	     .package = L"S-1-15-2-1",
	     .packageIdentity = fromRuleIdentity});
	identityPackages.missingPackageRules.push_back(
	    {.ruleId = L"family-rule",
	     .reference = PackageReference::PackageFamilyName,
	     .package = L"Derived.App_x",
	     .packageIdentity = derivedIdentity});
	UserOwnerAnalysis identityOwners;
	identityOwners.localProfileCheck = LocalProfileCheck::Completed;
	identityOwners.localUserOwnerRuleCount = 2;
	identityOwners.unresolvedSidRules.push_back(
	    {.ruleId = L"bad-sid-rule",
	     .localUserOwnerSid = L"not-a-sid",
	     .reason = UserOwnerResolveFailure::InvalidSidString,
	     .error = HRESULT_FROM_WIN32(ERROR_INVALID_SID),
	     .packageIdentity = notDerivedIdentity});
	identityOwners.missingLocalProfileRules.push_back(
	    {.ruleId = L"no-profile-rule",
	     .localUserOwnerSid = L"S-1-5-21-1-2-3-1002",
	     .domain = L"CONTOSO",
	     .user = L"alice",
	     .packageIdentity = idOnlyIdentity});
	DuplicateAnalysis identityDuplicates;
	identityDuplicates.duplicateSets.push_back(
	    {.duplicate_rule_begin = identityRules.begin(), .duplicate_rule_end = identityRules.end(), .nameCount = 1});
	identityDuplicates.duplicateRuleCount = 3;
	auto identityRecord = [](PCWSTR ruleId, const std::optional<RulePackageIdentity>& identity)
	{
		return RuleDeletionRecord{
		    .ruleId = ruleId,
		    .application = L"C:\\missing\\app.exe",
		    .localUserOwnerSid = L"not-a-sid",
		    .packageIdentity = identity,
		    .outcome = DeletionOutcome::Succeeded};
	};
	StoreCleanup identityCleanup;
	identityCleanup.actions.push_back(
	    {.reason = CleanupReason::MissingApplication,
	     .decision = CleanupDecision::Yes,
	     .approvalSource = ApprovalSource::Prompt,
	     .rules = {identityRecord(L"{c1}", derivedIdentity)}});
	identityCleanup.actions.push_back(
	    {.reason = CleanupReason::UnresolvedUserOwner,
	     .decision = CleanupDecision::Yes,
	     .approvalSource = ApprovalSource::Prompt,
	     .rules = {identityRecord(L"{c2}", notDerivedIdentity)}});
	identityCleanup.actions.push_back(
	    {.reason = CleanupReason::Duplicate,
	     .decision = CleanupDecision::No,
	     .rules = {identityRecord(L"{d1}", fromRuleIdentity), identityRecord(L"{d2}", std::nullopt)}});

	InitializeProfileJsonReport(outputPath, {L"-analyze-rules", L"-verbose"});
	WriteFirewallRuleStatusJson(identityStore, 0, identityCategories, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteApplicationAnalysisJson(identityStore, identityApplications, L"analyze_rules");
	WritePackageAnalysisJson(identityStore, identityPackages, L"analyze_rules");
	WriteUserOwnerAnalysisJson(identityStore, identityOwners, L"analyze_rules");
	WriteDuplicateAnalysisJson(identityStore, identityDuplicates, L"analyze_rules");
	WriteCleanupJson(identityStore, identityCleanup, L"analyze_rules", S_OK);
	const auto identityStoreRecord = FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_LOCAL);

	const auto statusRules = identityStoreRecord.GetNamedObject(L"ruleDetails")
	                             .GetNamedArray(L"categories")
	                             .GetAt(0)
	                             .GetObject()
	                             .GetNamedArray(L"rules");
	Check(
	    statusRules.Size() == 2 && hasIdentity(statusRules.GetAt(0).GetObject(), derivedIdentity) &&
	        hasIdentity(statusRules.GetAt(1).GetObject(), std::nullopt),
	    "Rule-status entries do not have their package identity.");
	Check(
	    keysInOrder(
	        PrettifyJson(statusRules.GetAt(0).GetObject()),
	        {L"ruleId", L"name", L"packageId", L"packageIdSource", L"packageFamilyName", L"status", L"statusHex"}),
	    "Rule-status entry package fields out of order.");

	const auto identityApplicationSection = identityStoreRecord.GetNamedObject(L"applicationAnalysis");
	const auto identityMissingApplications = identityApplicationSection.GetNamedArray(L"missingApplicationRules");
	Check(
	    hasIdentity(
	        identityApplicationSection.GetNamedArray(L"serviceProfileVariableRules").GetAt(0).GetObject(),
	        fromRuleIdentity) &&
	        hasIdentity(
	            identityApplicationSection.GetNamedArray(L"uncheckedApplicationRules").GetAt(0).GetObject(),
	            derivedIdentity) &&
	        hasIdentity(identityMissingApplications.GetAt(0).GetObject(), notDerivedIdentity) &&
	        hasIdentity(identityMissingApplications.GetAt(1).GetObject(), std::nullopt),
	    "Application entries do not have their package identity.");
	Check(
	    keysInOrder(
	        PrettifyJson(identityMissingApplications.GetAt(0).GetObject()),
	        {L"ruleId",
	         L"name",
	         L"application",
	         L"packageId",
	         L"packageIdSource",
	         L"packageIdError",
	         L"packageFamilyName",
	         L"reason",
	         L"error"}),
	    "Application entry package fields out of order.");

	const auto identityPackageSection = identityStoreRecord.GetNamedObject(L"packageAnalysis");
	Check(
	    hasIdentity(
	        identityPackageSection.GetNamedArray(L"missingPackageIdRules").GetAt(0).GetObject(),
	        fromRuleIdentity) &&
	        hasIdentity(
	            identityPackageSection.GetNamedArray(L"missingPackageFamilyNameRules").GetAt(0).GetObject(),
	            derivedIdentity),
	    "Package entries do not have their package identity.");

	const auto identityOwnerSection = identityStoreRecord.GetNamedObject(L"userOwnerAnalysis");
	const auto identityUnresolved = identityOwnerSection.GetNamedArray(L"unresolvedSidRules").GetAt(0).GetObject();
	const auto identityNoProfile = identityOwnerSection.GetNamedArray(L"missingLocalProfileRules").GetAt(0).GetObject();
	Check(
	    hasIdentity(identityUnresolved, notDerivedIdentity) && hasIdentity(identityNoProfile, idOnlyIdentity),
	    "SID-owner entries do not have their package identity.");
	Check(
	    keysInOrder(
	        PrettifyJson(identityUnresolved),
	        {L"ruleId",
	         L"name",
	         L"packageId",
	         L"packageIdSource",
	         L"packageIdError",
	         L"packageFamilyName",
	         L"localUserOwnerSid",
	         L"reason",
	         L"error"}) &&
	        keysInOrder(
	            PrettifyJson(identityNoProfile),
	            {L"packageId", L"packageIdSource", L"packageFamilyName", L"localUserOwnerSid", L"domain", L"user"}),
	    "SID-owner entry package fields out of order.");

	const auto identitySetRules = identityStoreRecord.GetNamedObject(L"duplicateAnalysis")
	                                  .GetNamedArray(L"duplicateSets")
	                                  .GetAt(0)
	                                  .GetObject()
	                                  .GetNamedArray(L"rules");
	Check(
	    identitySetRules.Size() == 3 && hasIdentity(identitySetRules.GetAt(0).GetObject(), derivedIdentity) &&
	        hasIdentity(identitySetRules.GetAt(1).GetObject(), fromRuleIdentity) &&
	        hasIdentity(identitySetRules.GetAt(2).GetObject(), std::nullopt),
	    "Duplicate set entries do not have their package identity.");

	const auto identityActions = identityStoreRecord.GetNamedObject(L"cleanup").GetNamedArray(L"actions");
	const auto identityOwnerAction = identityActions.GetAt(1).GetObject();
	const auto identityDuplicateRules = identityActions.GetAt(2).GetObject().GetNamedArray(L"rules");
	Check(
	    hasIdentity(identityActions.GetAt(0).GetObject(), derivedIdentity) &&
	        hasIdentity(identityOwnerAction, notDerivedIdentity) &&
	        hasIdentity(identityDuplicateRules.GetAt(0).GetObject(), fromRuleIdentity) &&
	        hasIdentity(identityDuplicateRules.GetAt(1).GetObject(), std::nullopt),
	    "Cleanup actions do not have their rules' package identity.");
	Check(
	    keysInOrder(
	        PrettifyJson(identityOwnerAction),
	        {L"action",
	         L"reason",
	         L"ruleId",
	         L"name",
	         L"packageId",
	         L"packageIdSource",
	         L"packageIdError",
	         L"packageFamilyName",
	         L"localUserOwnerSid",
	         L"decision",
	         L"outcome",
	         L"error"}),
	    "Cleanup action package fields out of order.");
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);

	// a rule whose application path could not be expanded is listed even without -verbose, and not counted
	// as missing
	InitializeProfileJsonReport(outputPath, {L"-analyze-rules"});
	WriteFirewallRuleStatusJson(statusStore, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
	WriteApplicationAnalysisJson(statusStore, uncheckedApplications, L"analyze_rules");
	const auto uncheckedSection =
	    FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_LOCAL).GetNamedObject(L"applicationAnalysis");
	const auto uncheckedRules = uncheckedSection.GetNamedArray(L"uncheckedApplicationRules");
	Check(
	    uncheckedSection.GetNamedString(L"status") == L"partial" &&
	        uncheckedSection.GetNamedNumber(L"uncheckedApplicationRuleCount") == 1 &&
	        uncheckedSection.GetNamedNumber(L"missingApplicationRuleCount") == 0 &&
	        !uncheckedSection.HasKey(L"missingApplicationRules") && uncheckedRules.Size() == 1,
	    "An unchecked application must make the section partial and be listed without -verbose.");
	const auto uncheckedEntry = uncheckedRules.GetAt(0).GetObject();
	Check(
	    uncheckedEntry.GetNamedString(L"ruleId") == L"unchecked-rule" &&
	        uncheckedEntry.GetNamedString(L"reason") == L"environment_expansion_failed" &&
	        uncheckedEntry.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070008",
	    "The unchecked application entry is incorrect.");

	// SID failures: a family-name failure is an error that makes the section partial; a full-name failure
	// is informational
	for (const auto& sidFailure : {familySidFailure, fullSidFailure})
	{
		const bool familyName = sidFailure.kind == PackageNameKind::FamilyName;
		PackageAnalysis withSidFailure;
		withSidFailure.sidFailures = {sidFailure};
		WriteFirewallRuleStatusJson(statusStore, 0, {}, L"analyze_rules", RuleStatusAnalysis::Performed);
		WritePackageAnalysisJson(statusStore, withSidFailure, L"analyze_rules");
		const auto sidSection =
		    FindJsonStoreObject(L"analyze_rules", FW_STORE_TYPE_LOCAL).GetNamedObject(L"packageAnalysis");
		const auto sidDiagnostics = sidSection.GetNamedArray(L"diagnostics");
		Check(
		    sidSection.GetNamedString(L"status") == (familyName ? L"partial" : L"completed") &&
		        sidDiagnostics.Size() == 1 &&
		        keysInOrder(
		            PrettifyJson(sidSection),
		            {L"status", L"missingPackageFamilyNameRuleCount", L"diagnostics"}),
		    "The package section status for a SID failure is incorrect.");
		const auto sidDiagnostic = sidDiagnostics.GetAt(0).GetObject();
		const auto sidSubject = sidDiagnostic.GetNamedObject(L"subject");
		Check(
		    sidDiagnostic.GetNamedString(L"severity") == (familyName ? L"error" : L"info") &&
		        sidDiagnostic.GetNamedString(L"code") == L"app_container_sid_not_derived" &&
		        sidDiagnostic.GetNamedString(L"operation") == L"derive_app_container_sid" &&
		        sidDiagnostic.GetNamedObject(L"error").GetNamedString(L"hex") == L"0x80070057" &&
		        sidSubject.GetNamedString(L"property") == L"installedPackages" &&
		        sidSubject.GetNamedString(familyName ? L"packageFamilyName" : L"packageFullName") ==
		            sidFailure.packageName &&
		        !sidSubject.HasKey(familyName ? L"packageFullName" : L"packageFamilyName"),
		    "The app_container_sid_not_derived diagnostic is incorrect.");
	}
	FinishProfileJsonReport(0, ReportRunOutcome::RanToEnd);

	std::printf(
	    "Profile, rule-status, application-analysis, package-analysis, SID-owner-analysis, filter-ranking, "
	    "duplicate-analysis, -clean-rules, package-identity, and result-status JSON tests passed.\n");
	return 0;
}
catch (const std::exception& ex)
{
	std::fprintf(stderr, "%s\n", ex.what());
	return 1;
}
