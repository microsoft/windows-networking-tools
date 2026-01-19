// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <iostream>
#include <numeric>
#include <vector>

#include <Windows.h>
#include <oaidl.h>
#include <combaseapi.h>
#include <netfw.h>

#include "FwDiagnose.h"

#include <thread>

#include "firewall.h"
#include "FirewallRules.h"
#include "NormalizedFirewallRule.h"
#include "WfpCounters.h"
#include "WfpEvents.h"

#include <wil/stl.h>
#include <wil/registry.h>
#include <wil/com.h>
#include <wil/result.h>

#include "AppContainers.h"

// manually turn on debug output for lower-level debugging
static bool g_debugOutputEnabled = false;
bool DebugOutputEnabled() noexcept
{
	return g_debugOutputEnabled;
}

static bool g_analyzeRules = false;
bool AnalyzeRulesEnabled() noexcept
{
	return g_analyzeRules;
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

static bool g_wfpEventEnumeration = false;
bool WfpEventEnumerationEnabled() noexcept
{
	return g_wfpEventEnumeration;
}

static bool g_deleteWfpCalloutFilters = false;
static bool DeleteWfpCalloutFiltersEnabled() noexcept
{
	return g_deleteWfpCalloutFilters;
}

static std::vector<FWPM_FILTER*> g_deletedWfpFilters;

static void RestoreDeletedFilters() noexcept
{
	if (g_deletedWfpFilters.empty())
	{
		return;
	}

	auto* const engine_handle = GetFwpmEngineHandle();
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
        "\n"
		"FwDiagnose.exe [options] [-verbose]\n"
        "\n"
		"  This utility provides options to analyze Windows Firewall rules and Windows Filter Platform filters.\n"
		"  It also has utility function to listen for and output NetEvents from WFP\n"
		"  as well as enumerating and writing out all App-Packages for troubleshooting.\n"
        "\n"
		"  Note that only one option can be specified with the optional -verbose flag.\n"
		"Options:\n"
		"  -?               : Show this help message.\n"
		"  -analyze-rules   : Analyzes firewall rules for potential issues\n"
		"  -clean-rules     : Prompts to delete duplicate rules\n"
		"                   : Prompts to delete rules with application exes referencing non-existing files\n"
		"                   : Prompts to delete rules referencing unknown SIDs\n"
		"                   : Prompts to delete isolation rules with a SIDs referencing non-existing profiles\n"
		"                   : This requires Administrator privileges\n"
		"  -analyze-wfp     : Output details of WFP objects (callouts, sublayers, and filters)\n"
		"                   : This requires Administrator privileges\n"
		"  -wfp-events      : Listen for and print all NetEvents from WFP\n"
		"  -remove-callouts : Prompt to temporarily remove filters for 3rd party WFP callout drivers\n"
		"                     Will restore any removed filters before this program exits\n"
		"  -list-app-packages : Output details of all app-container packages\n"
		"\n"
		"  -verbose         : Output details of rules and/or WFP objects\n");
}

int __cdecl main(int argc, char* argv[]) try
{
	const auto coInit = wil::CoInitializeEx();

	if (argc != 2 && argc != 3)
	{
		PrintUsage();
		return E_INVALIDARG;
	}

	std::vector<PCSTR> args(argv + 1, argv + argc);
	if (args.size() != 1 && args.size() != 2)
	{
		std::printf("An invalid parameter was specified (argument count of %zu)\n", args.size());
		std::printf("When specifying -verbose, only one other option can be used\n");
		PrintUsage();
		return E_INVALIDARG;
	}

	if (args.size() == 2)
	{
		// one of the 2 must be -verbose
		if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-verbose") == 0; }) != args.end())
		{
			auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-verbose") == 0; });
			args.erase(removed_args.cbegin(), args.end());
			g_verboseOutput = true;
		}
	}
	if (args.size() == 2)
	{
		// if we didn't remove the -verbose option, something invalid was specified
		std::printf("An invalid parameter was specified [%hs, %hs]\n", args[0], args[1]);
	    std::printf("When specifying -verbose, only one other option can be used\n");
		PrintUsage();
		return E_INVALIDARG;
	}

	if (std::ranges::find(args, "-?") != args.end())
	{
		PrintUsage();
		return 0;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-analyze-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-analyze-rules") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_analyzeRules = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-clean-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-clean-rules") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_cleanBrokenRules = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-analyze-wfp") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-wfp") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_wfpOutput = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-wfp-events") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-wfp-events") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_wfpEventEnumeration = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-remove-callouts") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-delete-callouts") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		// delete-callouts will automatically enable wfp output
		g_wfpOutput = true;
		g_deleteWfpCalloutFilters = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-list-app-packages") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-list-app-packages") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		LoadAllAppPackages();
		PrintAllAppPackages();
		return 0;
	}

	if (!args.empty())
	{
		std::printf("Unrecognized arguments: ");
		for (const auto& arg : args)
		{
			std::printf(" %s ", arg);
		}

		std::printf("\n");
		PrintUsage();
		return ERROR_BAD_ARGUMENTS;
	}

	// load Firewall, WFP, and AppContainer details
	auto wfp_thread = std::thread{
	[] {
		LoadWfpCallouts();
		LoadWfpSubLayers();
		LoadWfpProviders();
		LoadWfpFilters();
	} };
	auto firewall_thread = std::thread{ [] { LoadFirewallRules(); } };
	auto app_package_thread = std::thread{ [] { LoadAllAppPackages(); } };

	// joining in the order of expected time-to-complete
    // (WFP often taking a while)
	app_package_thread.join();
	firewall_thread.join();
	wfp_thread.join();

	if (AnalyzeRulesEnabled() || CleanBrokenRulesEnabled())
	{
		return ProcessFirewallRules();
	}

	if (WfpOutputEnabled())
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
		const std::vector<FilterDetails>& filter_details = ReadWfpFilters();
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

			const auto restore_deleted_filters_on_exit = wil::scope_exit([]
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
	else if (g_wfpEventEnumeration)
	{
		// verify has admin access
		if (!HasFirewallAdminAccess())
		{
			std::printf("  Administrative privileges required - try running from an elevated Administrator command prompt.\n");
			return ERROR_ACCESS_DENIED;
		}

		// sort filters by filter id for fast lookup
		SortFilterDetailsByFilterId();

		FWPM_NET_EVENT_SUBSCRIPTION0 subscription_info{};
		THROW_IF_FAILED(CoCreateGuid(&subscription_info.sessionKey));

		HANDLE eventsHandle{};
		const auto fwpm_subscription_error = FwpmNetEventSubscribe4(
			GetFwpmEngineHandle(),
			&subscription_info,
			[](void*, const FWPM_NET_EVENT5* event)
			{
				try
				{
					std::printf(
						"\n** NetEvent received **\n"
						"%ls"
						"%ls"
						"%ls",
						PrintNetEventType(event).c_str(),
						PrintNetEventHeader(event).c_str(),
						PrintNetEventDetailedStruct(event).c_str());
					if (event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP)
					{
						std::printf("   * Classify Drop Event\n");

						const auto& found_filter = FindFilterByFilterId(event->classifyDrop->filterId);
						std::printf("     * Filter name: %ls\n", found_filter.name.value.c_str());
						std::printf("     * Filter description: %ls\n", found_filter.description.c_str());
						if (found_filter.InvokesCallout())
						{
							std::printf("     * Filter invokes callout: %ls\n", PrintCallout(found_filter.action_type.calloutKey).c_str());
						}

						const auto& found_sublayer = FindSublayer(found_filter.subLayerKey);
						std::printf("     * Filter layer: %hs\n", LayerToString(found_filter.layerKey).c_str());
						std::printf("     * Filter sublayer: %ls\n", SublayerToSimpleString(found_sublayer).c_str());
					}
				}
				catch (const std::exception& ex)
				{
					std::printf("\n*** An error occurred processing a NetEvent: %hs\n", ex.what());
				}
			},
			nullptr, // null context
			&eventsHandle);
		THROW_IF_WIN32_ERROR_MSG(fwpm_subscription_error, "FwpmNetEventSubscribe4");

		std::printf(
			"\n"
			"**************************************************************************************\n"
			"                            Subscribed to WFP NetEvents                               \n"
			"                      ( press Ctrl-C to stop processing events )                      \n"
			"**************************************************************************************\n");

		static const wil::unique_event ctrl_event(wil::EventOptions::ManualReset);
		SetConsoleCtrlHandler(
			[](DWORD) ->BOOL
			{
				ctrl_event.SetEvent();
				return TRUE;
			},
			TRUE);
		(void)ctrl_event.wait();

		const auto fwpm_unsubscribe_error = FwpmNetEventUnsubscribe0(GetFwpmEngineHandle(), eventsHandle);
		THROW_IF_WIN32_ERROR_MSG(fwpm_unsubscribe_error, "FwpmNetEventUnsubscribe0");

		std::printf("\n**  Exiting  **\n");

		/*
		FWPM_NET_EVENT_ENUM_TEMPLATE0 enum_template{};
		enum_template.numFilterConditions = 0;
		enum_template.filterCondition = nullptr;
		SYSTEMTIME system_time{};
		GetSystemTime(&system_time);
		SystemTimeToFileTime(&system_time, &enum_template.endTime);
		system_time.wMinute -= 10; // look back 10 minutes
		SystemTimeToFileTime(&system_time, &enum_template.startTime);

		HANDLE enumHandle{};
		auto create_enum_error = FwpmNetEventCreateEnumHandle0(
			GetFwpmEngineHandle(),
			&enum_template,
			&enumHandle);
		THROW_IF_WIN32_ERROR_MSG(create_enum_error, "FwpmNetEventCreateEnumHandle0");
		const auto close_enum_handle_on_exit = wil::scope_exit(
			[&] {
				if (enumHandle)
				{
					FwpmNetEventDestroyEnumHandle0(GetFwpmEngineHandle(), enumHandle);
				}
			});

		for (;;)
		{
			FWPM_NET_EVENT5** net_event_array{};
			UINT32 entries_returned{};
			create_enum_error = FwpmNetEventEnum5(
				GetFwpmEngineHandle(),
				enumHandle,
				10,
				&net_event_array,
				&entries_returned);
			if (create_enum_error != ERROR_SUCCESS)
			{
				std::printf("  * No more NetEvents to enumerate (%lu)\n", create_enum_error);
				break;
			}
			const auto free_memory_on_exit = wil::scope_exit(
				[&]
				{
					if (net_event_array)
					{
						FwpmFreeMemory0(reinterpret_cast<void**>(net_event_array));
					}
				});
			for (UINT32 i = 0; i < entries_returned; ++i)
			{
				const auto* current_event = net_event_array[i];
				std::printf(
					"- NetEvent %u\n"
					"%ls\n"
					"%ls\n"
					"%ls\n",
					i + 1,
					PrintNetEventType(current_event).c_str(),
					PrintNetEventHeader(current_event).c_str(),
					PrintNetEventDetailedStruct(current_event).c_str());
				if (current_event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP)
				{
					std::printf("   * Classify Drop Event\n");
					const auto& found_filter = FindFilterByFilterId(current_event->classifyDrop->filterId);
					std::printf("     * Found matching filter: %llu\n", found_filter.filterId);
					std::printf("     * Filter name: %ls\n", found_filter.name.value.c_str());
					std::printf("     * Filter description: %ls\n", found_filter.description.c_str());

					const auto& found_sublayer = FindSublayer(found_filter.subLayerKey);
					std::printf("     * Filter layer: %hs\n", LayerToString(found_filter.layerKey).c_str());
					std::printf("     * Filter sublayer: %ls\n", SublayerToString(found_sublayer).c_str());
				}
			}
		}
*/
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
