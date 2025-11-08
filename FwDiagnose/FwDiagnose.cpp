// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <iostream>
#include <numeric>
#include <vector>

#include <Windows.h>

#include "FwDiagnose.h"
#include "firewall.h"
#include "FirewallRules.h"
#include "NormalizedFirewallRule.h"
#include "WfpCounters.h"

#include <wil/stl.h>
#include <wil/registry.h>
#include <wil/resource.h>

// not static - shared with other files
static bool g_debugPrint = false;
bool DebugPrintEnabled() noexcept
{
	return g_debugPrint;
}

static bool g_cleanBrokenRules = false;
bool CleanBrokenRulesEnabled() noexcept
{
	return g_cleanBrokenRules;
}

static bool g_verboseOutput = false;
bool VerboseOutputEnabled() noexcept
{
	return g_verboseOutput;
}

static bool g_wfpOutput = false;
bool WfpOutputEnabled() noexcept
{
	return g_wfpOutput;
}

static bool g_deleteWfpCalloutFilters = false;

static bool DeleteWfpCalloutFiltersEnabled() noexcept
{
	return g_deleteWfpCalloutFilters;
}

static FirewallPolicyObjects g_policy_objects[] =
{
	{.type = FW_STORE_TYPE_LOCAL,            .type_string = "Local", .normalizedRules = {}},
	// { .type= FW_STORE_TYPE_DYNAMIC, .type_string= "Dynamic", .normalizedRules = {}},
	{.type = FW_STORE_TYPE_GPO,              .type_string = "Group Policy", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_GP_RSOP,          .type_string = "Group Policy (RSOP)", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_WSH_STATIC,       .type_string = "Windows Service Hardening (Static)", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_WSH_CONFIGURABLE, .type_string = "Windows Service Hardening (Configurable)", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_IF_ISO,           .type_string = "Interface-Isolation", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_IF_ISO_DYNAMIC,   .type_string = "Interface-Isolation (Dynamic)", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_APP_ISO,          .type_string = "Application-Isolation", .normalizedRules = {} },
	{.type = FW_STORE_TYPE_MDM,              .type_string = "Mobile-Device-Management (MDM)" , .normalizedRules = {}},
	{.type = FW_STORE_TYPE_TENANT_RESTRICTIONS, .type_string = "Tenant Restrictions", .normalizedRules = {} }
};

static std::vector<FWPM_FILTER*> g_deletedWfpFilters;

static void RestoreDeletedFilters() noexcept
{
	if (g_deletedWfpFilters.empty())
	{
		return;
	}

	const auto engine_handle = GetFwpmEngineHandle();
	for (auto& filter : g_deletedWfpFilters)
	{
		if (filter)
		{
			const auto fwpm_error = FwpmFilterAdd0(
				engine_handle,
				filter,
				nullptr,
				nullptr);
			if (fwpm_error != ERROR_SUCCESS)
			{
				std::printf("Failed to restore deleted WFP filter %llu. Error: 0x%lx\n", filter->filterId, fwpm_error);
			}
			else
			{
				std::printf("Restored deleted WFP filter %llu\n", filter->filterId);
			}

			FwpmFreeMemory(reinterpret_cast<void**>(&filter));
		}
	}
	g_deletedWfpFilters.clear();
}

static void PrintUsage() noexcept
{
	std::printf(
		"Usage: FwDiagnose.exe [-clean] [-verbose] [-wfp]\n"
		"This tool enumerates the local firewall rules and checks for errors, duplicates, and missing application files.\n"
		"This tool also enumerates WFP objects (callouts, sublayers, providers, and filters)\n"
		"Options:\n"
		"  -?               : Show this help message.\n"
		"  -clean-rules     : Prompts to delete duplicate rules\n"
		"                   : Prompts to delete rules with application exes referencing non-existing files\n"
		"                   : Prompts to delete rules referencing unknown SIDs\n"
		"                   : Prompts to delete isolation rules with a SIDs referencing non-existing profiles\n"
		"                   : This requires Administrator privileges\n"
		"  -wfp             : Output details of WFP objects (callouts, sublayers, and filters)\n"
		"                   : This requires Administrator privileges\n"
		"  -delete-callouts : Prompt to temporarily delete filters for 3rd party WFP callout drivers\n"
		"                     Will restore any deleted filters before this program exits\n"
		"  -verbose         : Output details of rules and/or WFP objects\n"
		"\n"
		"Note: -wfp and -clean-rules cannot both be specified");
}
int __cdecl main(int argc, char* argv[]) try
{
	const auto coInit = wil::CoInitializeEx();
	const auto wmi_supported = InitializeWfpPerfCounters();

	std::vector<std::string> args;
	for (int i = 1; i < argc; ++i)
	{
		args.emplace_back(argv[i]);
	}

	if (!args.empty())
	{
		if (std::ranges::find(args, "-?") != args.end())
		{
			PrintUsage();
			return 0;
		}

		if (std::ranges::find(args, "-debug") != args.end())
		{
			auto removed_args = std::ranges::remove_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-debug") == 0; });
			args.erase(removed_args.cbegin(), args.end());
			g_debugPrint = true;
		}

		if (std::ranges::find_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-clean-rules") == 0; }) != args.end())
		{
			auto removed_args = std::ranges::remove_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-clean-rules") == 0; });
			args.erase(removed_args.cbegin(), args.end());
			g_cleanBrokenRules = true;
		}

		if (std::ranges::find_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-verbose") == 0; }) != args.end())
		{
			auto removed_args = std::ranges::remove_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-verbose") == 0; });
			args.erase(removed_args.cbegin(), args.end());
			g_verboseOutput = true;
		}

		if (std::ranges::find_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-wfp") == 0; }) != args.end())
		{
			auto removed_args = std::ranges::remove_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-wfp") == 0; });
			args.erase(removed_args.cbegin(), args.end());
			g_wfpOutput = true;
		}

		if (std::ranges::find_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-delete-callouts") == 0; }) != args.end())
		{
			auto removed_args = std::ranges::remove_if(args, [&](const auto& lhs) { return _stricmp(lhs.c_str(), "-delete-callouts") == 0; });
			args.erase(removed_args.cbegin(), args.end());
			// delete-callouts will automatically enable wfp output
			g_wfpOutput = true;
			g_deleteWfpCalloutFilters = true;
		}

		if (!args.empty())
		{
			std::printf("Unrecognized arguments: ");
			for (const auto& arg : args)
			{
				std::printf(" %s ", arg.c_str());
			}

			std::printf("\n");
			PrintUsage();
			return ERROR_BAD_ARGUMENTS;
		}

		if (g_wfpOutput && g_cleanBrokenRules)
		{
			std::printf("The -wfp and -clean-rules options cannot both be specified\n");
			PrintUsage();
			return ERROR_BAD_ARGUMENTS;
		}

		if (g_deleteWfpCalloutFilters && !g_wfpOutput)
		{
			std::printf("The -disable_callout option requires the -wfp option to also be specified\n");
			PrintUsage();
			return ERROR_BAD_ARGUMENTS;
		}
	}

	ChronoTimer timer;

	LoadFirewallFunctions();

	if (!g_wfpOutput)
	{
		// if we are deleting rules, capture filter counts before and after
		uint64_t initial_filter_count = 0;
		if (wmi_supported && CleanBrokenRulesEnabled())
		{
			initial_filter_count = ReadWfpPerfCounters();
		}

		std::wstring banner_header;
		banner_header.insert(banner_header.begin(), 86, L'*');

		for (auto& policy : g_policy_objects)
		{
			// cannot directly modify MDM or GP rules locally
			if (CleanBrokenRulesEnabled())
			{
				if (policy.type == FW_STORE_TYPE_MDM ||
					policy.type == FW_STORE_TYPE_GPO ||
					policy.type == FW_STORE_TYPE_GP_RSOP ||
					policy.type == FW_STORE_TYPE_WSH_STATIC ||
					policy.type == FW_STORE_TYPE_WSH_CONFIGURABLE)
				{
					std::printf(
						"\n"
						"%ls\n"
						"  Skipping the %hs Firewall Policy Store\n"
						"%ls\n"
						"  NOTE: The %hs Firewall Policy Store cannot be modified locally.\n"
						"        Skipping any deletion of rules in this store.\n",
						banner_header.c_str(),
						policy.type_string,
						banner_header.c_str(),
						policy.type_string);
					continue;
				}
			}
			try
			{
				auto banner_output = wil::str_printf<std::wstring>(L"Analyzing the %hs Firewall Policy Store", policy.type_string);
				const size_t prefix_spaces = (banner_header.size() - banner_output.size()) / 2;
				banner_output.insert(0, prefix_spaces, L' ');

				std::printf(
					"\n"
					"%ls\n"
					"%ls\n"
					"%ls\n",
					banner_header.c_str(),
					banner_output.c_str(),
					banner_header.c_str());

				timer.start("LoadFirewallRulesFromStore");
				const auto load_error = LoadFirewallRulesFromStore(policy);
				timer.end();
				if (FAILED(load_error))
				{
					if (load_error == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
					{
						continue;
					}
					THROW_HR(load_error);
				}

				timer.start("CheckForRulesWithErrorStatus");
				CheckForRulesWithErrorStatus(policy.normalizedRules);
				timer.end();

				if (g_verboseOutput)
				{
					std::printf("\n");
				}
				timer.start("CheckForMissingAppRules");
				CheckForMissingAppRules(policy.normalizedRules);
				timer.end();

				if (CleanBrokenRulesEnabled())
				{
					std::printf("\n");
					DeleteMissingAppRules(policy.normalizedRules);
				}

				if (g_verboseOutput)
				{
					std::printf("\n");
				}
				timer.start("CheckUnresolvedUserAccountRules");
				CheckUnresolvedUserAccountRules(policy.normalizedRules, policy.type);
				timer.end();

				if (CleanBrokenRulesEnabled())
				{
					std::printf("\n");
					DeleteUnresolvedUserAccountRules(policy.normalizedRules);
				}

				if (g_verboseOutput)
				{
					std::printf("\n");
				}
				timer.start("Counting duplicate rules");
				const auto duplicateRules = CheckForDuplicateRules(policy.normalizedRules);
				timer.end();

				if (CleanBrokenRulesEnabled())
				{
					std::printf("\n");
					DeleteDuplicateRules(duplicateRules);
				}
			}
			catch (const wil::ResultException& ex)
			{
				std::printf(" -- an error occurred (0x%lx) -- \n", ex.GetErrorCode());  // NOLINT(clang-diagnostic-format)
			}
		}

		if (wmi_supported)
		{
			const uint64_t final_wfp_filter_count = ReadWfpPerfCounters();
			// if we are deleting rules, capture filter counts before and after
			if (CleanBrokenRulesEnabled())
			{
				std::printf(
					"\n"
					"**************************************************************************************\n"
					"                              Perf Counters: WFP Filters                              \n"
					"**************************************************************************************\n"
					"  * Total filters before removing rules: %llu\n"
					"  * Total filters after removing rules: %llu\n",
					initial_filter_count,
					final_wfp_filter_count);
			}
			else
			{
				std::printf(
					"\n"
					"**************************************************************************************\n"
					"                              Perf Counters: WFP Filters                              \n"
					"**************************************************************************************\n"
					"  * Total filters: %llu\n",
					final_wfp_filter_count);
			}
		}
	}
	else
	{
		// verify has admin access
		if (!HasFirewallAdminAccess())
		{
			std::printf("  Administrative privileges required - try running from an elevated Administrator command prompt.\n");
			return ERROR_ACCESS_DENIED;
		}

		std::printf(
			"\n"
			"**************************************************************************************\n"
			"                                     WFP Callouts                                     \n"
			"**************************************************************************************\n");
		auto& wfp_callouts = ReadWfpCallouts();
		std::printf(
			"  * Total callouts: %zu\n"
			"  * Total 3rd party callouts: %zd\n",
			wfp_callouts.size(),
			std::ranges::count_if(
				wfp_callouts, [](const CalloutDetails& callout)
				{
					return callout.is_third_party_callout;
				}));
		for (const auto& callout : wfp_callouts)
		{
			if (callout.is_third_party_callout)
			{
				std::printf("       %ls [callout id: %u] [%ls]\n",
					callout.name.empty() ? L"(no name)" : callout.name.c_str(),
					callout.callout_id,
					callout.driver_name.empty() ? L"(hidden)" : callout.driver_name.c_str());
			}
		}

		if (g_verboseOutput)
		{
			GUID current_layer_being_printed{};
			for (const auto& callout : wfp_callouts)
			{
				if (current_layer_being_printed != callout.applicable_layer)
				{
					current_layer_being_printed = callout.applicable_layer;
					std::printf("\n    %hs\n", callout.layer.c_str());
				}

				std::printf("      %ls\n", PrintCallout(callout).c_str());
			}
		}

		std::printf(
			"\n"
			"**************************************************************************************\n"
			"                                     WFP Sublayers                                    \n"
			"**************************************************************************************\n");
		const auto& wfp_sublayers = ReadWfpSubLayers();
		std::printf(
			"  * Total sublayers: %zu\n"
			"  * Total 3rd party sublayers: %zd\n",
			wfp_sublayers.size(),
			std::ranges::count_if(
				wfp_sublayers, [](const SubLayerDetails& sublayer)
				{
					return sublayer.is_third_party_sublayer;
				}));
		for (const auto& sublayer : wfp_sublayers)
		{
			if (sublayer.is_third_party_sublayer)
			{
				std::printf("      %ls [weight %hu]\n", sublayer.displayName.empty() ? L"(no display name)" : sublayer.displayName.c_str(), sublayer.weight);
			}
		}

		if (g_verboseOutput)
		{
			for (const auto& sublayer : wfp_sublayers)
			{
				std::printf("    %ls\n", SublayerToString(sublayer).c_str());
			}
			std::printf("\n");
		}


		std::printf(
			"\n"
			"**************************************************************************************\n"
			"                                     WFP Providers                                    \n"
			"**************************************************************************************\n");
		const auto& wfp_providers = ReadWfpProviders();
		std::printf("  * Total Providers: %zu\n"
			"  * Total 3rd party providers: %zd\n",
			wfp_providers.size(),
			std::ranges::count_if(
				wfp_providers, [](const ProviderDetails& provider)
				{
					return provider.is_third_party_provider;
				}));
		for (const auto& provider : wfp_providers)
		{
			if (provider.is_third_party_provider)
			{
				std::printf("      %ls\n", provider.displayName.empty() ? L"(no display name)" : provider.displayName.c_str());
			}
		}

		if (g_verboseOutput)
		{
			for (const auto& provider : wfp_providers)
			{
				std::printf("    %ls\n", ProviderToString(provider).c_str());
			}
		}

		std::printf(
			"\n"
			"**************************************************************************************\n"
			"                                     WFP Filters                                      \n"
			"**************************************************************************************\n");
		// ReadWfpFilters will also update SubLayers and Provider counts regarding # of filters in each
		const auto& filter_details = ReadWfpFilters(g_verboseOutput);
		size_t filter_count = 0;
		size_t disabled_count = 0;
		size_t persistent_count = 0;
		size_t filter_count_without_provider = 0;
		for (const auto& current_fwpm_filter : filter_details)
		{
			++filter_count;
			if (current_fwpm_filter.flags & FWPM_FILTER_FLAG_DISABLED)
			{
				++disabled_count;
			}
			if (current_fwpm_filter.flags & FWPM_FILTER_FLAG_PERSISTENT)
			{
				++persistent_count;
			}
			if (!current_fwpm_filter.providerKey.has_value())
			{
				++filter_count_without_provider;
			}
		}
		std::printf("\n");
		std::printf("  * Total filters: %zu\n", filter_count);
		std::printf("    * Disabled filters: %zu\n", disabled_count);
		std::printf("    * Persistent filters: %zu\n", persistent_count);
		if (g_verboseOutput)
		{
			std::printf("\n");
			std::printf("  * Filter counts per sublayer\n");
			PrintSublayerFilterDetails();

			std::printf("\n");
			std::printf("  * Filter counts per provider\n");
			std::printf("    * Filters without provider: %zu\n", filter_count_without_provider);
			PrintProviderFilterDetails();
		}

		// updates which callouts are referenced by filters
		for (const auto& current_fwpm_filter : filter_details)
		{
			if (current_fwpm_filter.InvokesCallout())
			{
				auto found_callout =
					std::ranges::find_if(
						wfp_callouts,
						[&](const CalloutDetails& callout) {
							return callout.callout_key == current_fwpm_filter.action_type.calloutKey;
						});
				if (found_callout == wfp_callouts.end())
				{
					std::printf("  ** WARNING: Filter %ls references a callout that is not present on the system: %ls\n", \
						current_fwpm_filter.name.value.c_str(),
						GuidToString(current_fwpm_filter.action_type.calloutKey).c_str());
				}
				else
				{
					if (current_fwpm_filter.IsDisabled())
					{
						++found_callout->referenced_by_filter_count_disabled;
					}
					else
					{
						++found_callout->referenced_by_filter_count_enabled;
					}

				}
			}
		}

		// resort callouts by # of filters referencing them
		std::ranges::sort(
			wfp_callouts,
			[](const CalloutDetails& lhs, const CalloutDetails& rhs) noexcept
			{
				if (lhs.referenced_by_filter_count_enabled > rhs.referenced_by_filter_count_enabled)
				{
					return true;
				}
				if (lhs.referenced_by_filter_count_enabled < rhs.referenced_by_filter_count_enabled)
				{
					return false;
				}
				return GuidToString(lhs.callout_key) < GuidToString(rhs.callout_key);
			}
		);

		if (g_verboseOutput)
		{
			std::printf("\n");
		}
		std::printf("  * Total enabled filters that invoke a callout (FWP_ACTION_FLAG_CALLOUT): %llu [3rd party callout filters: %llu]\n",
			std::accumulate(
				wfp_callouts.begin(),
				wfp_callouts.end(),
				0ull,
				[](uint64_t sum, const CalloutDetails& callout) {
					return sum + callout.referenced_by_filter_count_enabled;
				}
			),
			std::accumulate(
				wfp_callouts.begin(),
				wfp_callouts.end(),
				0ull,
				[](uint64_t sum, const CalloutDetails& callout) {
					return sum + (callout.is_third_party_callout ? callout.referenced_by_filter_count_enabled : 0);
				}
			)
		);
		std::printf("  * Total disabled filters that invoke a callout (FWP_ACTION_FLAG_CALLOUT): %llu [3rd party callout filters: %llu]\n",
			std::accumulate(
				wfp_callouts.begin(),
				wfp_callouts.end(),
				0ull,
				[](uint64_t sum, const CalloutDetails& callout) {
					return sum + callout.referenced_by_filter_count_disabled;
				}
			),
			std::accumulate(
				wfp_callouts.begin(),
				wfp_callouts.end(),
				0ull,
				[](uint64_t sum, const CalloutDetails& callout) {
					return sum + (callout.is_third_party_callout ? callout.referenced_by_filter_count_disabled : 0);
				}
			)
		);

		std::printf("    * 3rd party callouts filters\n");
		for (const auto& callout : wfp_callouts)
		{
			if (callout.is_third_party_callout)
			{
				const auto internal_string = GetInternalCalloutString(callout);
				std::printf("      callout id %ld : [%llu filters enabled] [%llu filters disabled] [callout name: %ls] [driver name: %ls]\n",
					callout.callout_id,
					callout.referenced_by_filter_count_enabled,
					callout.referenced_by_filter_count_disabled,
					internal_string.empty() ? callout.name.c_str() : internal_string.c_str(),
					callout.driver_name.empty() ? L"(hidden)" : callout.driver_name.c_str()
				);

				for (const auto& current_fwpm_filter : filter_details)
				{
					if (current_fwpm_filter.InvokesCallout(callout.callout_key))
					{
						// find what sublayer their callout is in
						std::wstring filter_sublayer;
						for (const auto& sublayer : wfp_sublayers)
						{
							if (sublayer.subLayerKey == current_fwpm_filter.subLayerKey)
							{
								filter_sublayer = sublayer.displayName;
								break;
							}
						}

						std::printf("        - filter id %llu : [filter name: %ls] [layer: %hs] [sublayer: %ls]\n",
							current_fwpm_filter.filterId,
							current_fwpm_filter.name.value.c_str(),
							LayerToString(current_fwpm_filter.layerKey).c_str(),
							filter_sublayer.c_str());
					}
				}
			}
		}

		if (g_verboseOutput)
		{
			std::printf("\n    * Filters per Callout\n");
			for (const auto& callout : wfp_callouts)
			{
				if (callout.referenced_by_filter_count_enabled > 0)
				{
					const auto internal_string = GetInternalCalloutString(callout);
					std::printf("      %ls : [%llu filters enabled] [%llu filters disabled] [callout name: %ls]\n",
						GuidToString(callout.callout_key).c_str(),
						callout.referenced_by_filter_count_enabled,
						callout.referenced_by_filter_count_disabled,
						internal_string.empty() ? callout.name.c_str() : internal_string.c_str()
					);
				}
			}
		}

		if (VerboseOutputEnabled())
		{
			// update which rules are referenced by filters
			for (auto& policy : g_policy_objects)
			{
				timer.start("LoadFirewallRulesFromStore");
				const auto load_error = LoadFirewallRulesFromStore(policy);
				timer.end();
				if (FAILED(load_error))
				{
					if (load_error == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
					{
						continue;
					}
					THROW_HR(load_error);
				}
				timer.end();

				// sort vectors of rules/filters by name so can do a binary search for rules by name
				std::ranges::sort(
					policy.normalizedRules,
					[](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
					{
						return lhs.ruleName < rhs.ruleName;
					}
				);
				SortFilterDetailsByName();

				size_t rule_name_count = 0;
				decltype(policy.normalizedRules.begin()) previous_iter{};
				for (auto iter = policy.normalizedRules.begin(); iter != policy.normalizedRules.end(); ++iter)
				{
					if (iter == policy.normalizedRules.begin())
					{
						previous_iter = iter;
						continue;
					}

					const auto& rule_name = iter->ruleName;
					const auto& previous_rule_name = previous_iter->ruleName;
					if (rule_name == previous_rule_name)
					{
						if (rule_name_count == 0)
						{
							// first time we have seen this duplicate
							rule_name_count = 2;
						}
						else
						{
							// have already seen this duplicate before
							++rule_name_count;
						}
					}
					else
					{
						// found a new unique firewall rule - check how many filters exist for the previous rule name
						previous_iter->filter_count = CountFiltersByName(previous_rule_name);
						previous_iter->filter_condition_count = CountFilterConditionsByName(previous_rule_name);
						previous_iter->duplicate_rule_count = rule_name_count == 0 ? 1 : rule_name_count;
						rule_name_count = 0;
					}

					previous_iter = iter;
				}

				if (!policy.normalizedRules.empty())
				{
					// resort rules by # of filters
					std::ranges::sort(
						policy.normalizedRules,
						[](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
						{
							return lhs.filter_count > rhs.filter_count;
						}
					);
					// write out the top 10 rules referenced by filters
					std::printf("\n");
					std::printf("  * Firewall Policy Store %s : Top 10 Firewall rules based off of total numbers of filters\n", policy.type_string);
					size_t rules_printed = 0;
					for (const auto& rule_details : policy.normalizedRules)
					{
						if (rule_details.filter_count == 0)
						{
							// remaining rules are not referenced by any filters
							break;
						}

						std::printf("    [%zu] '%ls' across %zu %ls with this name\n",
							rule_details.filter_count,
							rule_details.ruleName.value.c_str(),
							rule_details.duplicate_rule_count,
							rule_details.duplicate_rule_count > 0 ? L"rules" : L"rule");

						++rules_printed;
						if (rules_printed >= 10)
						{
							break;
						}
					}

					// resort rules by # of filters conditions
					std::ranges::sort(
						policy.normalizedRules,
						[](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
						{
							return lhs.filter_condition_count > rhs.filter_condition_count;
						}
					);
					// write out the top 10 rules referenced by filters
					std::printf("\n");
					std::printf("  * Firewall Policy Store %s : Top 10 Firewall rules based off of filter conditions/rule\n",
						policy.type_string);
					rules_printed = 0;
					for (const auto& rule_details : policy.normalizedRules)
					{
						if (rule_details.filter_condition_count == 0)
						{
							// remaining rules are not referenced by any filters
							break;
						}

						std::printf("    [%zu] '%ls' across %zu %ls with this name\n",
							rule_details.filter_condition_count,
							rule_details.ruleName.value.c_str(),
							rule_details.duplicate_rule_count,
							rule_details.duplicate_rule_count > 0 ? L"rules" : L"rule");

						++rules_printed;
						if (rules_printed >= 10)
						{
							break;
						}
					}
				}
			}
		}

		if (DeleteWfpCalloutFiltersEnabled())
		{
			std::printf(
				"\n"
				"**************************************************************************************\n"
				"               Temporarily Deleting Filters for 3rd Party WFP Callouts                \n"
				"**************************************************************************************\n");
			std::vector<std::wstring> callout_drivers;
			for (const auto& callout : wfp_callouts)
			{
				if (callout.is_third_party_callout)
				{
					if (callout.driver_name.empty())
					{
						continue;
					}
					if (std::ranges::find(callout_drivers, callout.driver_name) != callout_drivers.end())
					{
						continue;
					}
					callout_drivers.emplace_back(callout.driver_name);
				}
			}
			std::printf(
				"  * Total 3rd party callout drivers: %zu\n",
				callout_drivers.size());
			for (const auto& driver_name : callout_drivers)
			{
				std::printf("    - %ls\n", driver_name.c_str());
			}

			const auto restore_deleted_filters_on_exit = wil::scope_exit([]()
				{
					RestoreDeletedFilters();
				});

			bool delete_all_with_no_more_prompts = false;
			for (const auto& driver : callout_drivers)
			{
				std::printf("\n  * Temporarily deleting filters for the callout driver: %ls\n", driver.c_str());
				for (const auto& callout : wfp_callouts)
				{
					if (callout.driver_name != driver)
					{
						continue;
					}

					std::printf(
						"\n"
						"    * Temporarily deleting the filters for WFP callout %ls - registered with driver %ls\n"
						"       Callout id %ld\n"
						"       Filters for this callout: %llu\n",
						callout.name.c_str(),
						callout.driver_name.c_str(),
						callout.callout_id,
						callout.referenced_by_filter_count_enabled + callout.referenced_by_filter_count_disabled);

					if (callout.referenced_by_filter_count_enabled + callout.referenced_by_filter_count_disabled == 0)
					{
						std::printf("      * No Filters to delete for this callout\n");
						continue;
					}

					bool skip_remaining_callouts = false;
					if (!delete_all_with_no_more_prompts)
					{
						const auto DeletionPrompt = wil::str_printf<std::wstring>(L"Temporarily delete all filters referencing this callout (%ls) referencing driver (%ls)", callout.name.c_str(), callout.driver_name.c_str());
						switch (PromptForDeletion(DeletionPrompt.c_str()))
						{
						case PromptResponse::Yes:
							// continue to delete filters for this callout
							break;

						case PromptResponse::No:
							std::printf("       - Skipping filters for this one callout (%ls)\n", callout.name.c_str());
							skip_remaining_callouts = true;
							continue;

						case PromptResponse::Skip:
							std::printf("       - Skipping the remainder of the callouts for this driver (%ls)\n", driver.c_str());
							skip_remaining_callouts = true;
							break;

						case PromptResponse::All:
							std::printf("       - Deleting all filters referencing all callouts for all drivers\n");
							delete_all_with_no_more_prompts = true;
							break;
						}
					}
					if (skip_remaining_callouts)
					{
						break;
					}

					std::printf("       - Temporarily deleting filters referencing this callout\n");
					for (const auto& current_fwpm_filter : filter_details)
					{
						if (current_fwpm_filter.InvokesCallout(callout.callout_key))
						{
							std::printf("         Temporarily deleting filter id %llu : [filter name: %ls] [layer: %hs]\n",
								current_fwpm_filter.filterId,
								current_fwpm_filter.name.value.c_str(),
								LayerToString(current_fwpm_filter.layerKey).c_str());

							FWPM_FILTER* deleted_filter{};
							// ensure we have space in our vector before deleting the filter
							g_deletedWfpFilters.push_back(deleted_filter);
							const auto filter_get_error = FwpmFilterGetByKey(GetFwpmEngineHandle(), &current_fwpm_filter.filterKey, &deleted_filter);
							if (filter_get_error != 0)
							{
								std::printf("         - FwpmFilterGetByKey failed: 0x%lx -- cannot delete filter %llu\n", filter_get_error, current_fwpm_filter.filterId);
							}
							else
							{
								const auto delete_error = FwpmFilterDeleteByKey(GetFwpmEngineHandle(), &current_fwpm_filter.filterKey);
								if (delete_error != 0)
								{
									std::printf("         - FwpmFilterDeleteByKey failed: 0x%lx\n", delete_error);
								}
								else
								{
									*g_deletedWfpFilters.rbegin() = deleted_filter;
								}
							}
						}
					}
				}
			}

			// work hard to guarantee we restore the filters we deleted
			SetConsoleCtrlHandler([](DWORD) -> BOOL
				{
					std::printf("Restoring filters to callout drivers...\n");
					RestoreDeletedFilters();
					TerminateProcess(GetCurrentProcess(), 0);
					return TRUE;
				}, TRUE);
			std::printf("Press Enter to restore filters to callout drivers\n");
			std::wstring userInput;
			std::getline(std::wcin, userInput);

			std::printf("Restoring filters to callout drivers...\n");
			RestoreDeletedFilters();
		}
	}

	return 0;
}
catch (const wil::ResultException& ex)
{
	std::printf("\n*** An error occurred (0x%lx): %hs\n", ex.GetErrorCode(), ex.what());  // NOLINT(clang-diagnostic-format)
	return ex.GetErrorCode();
}
catch (const std::exception& ex)
{
	std::printf("\n*** An error occurred: %hs\n", ex.what());
	return ERROR_INTERNAL_ERROR;
}