// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <numeric>
#include <thread>
#include <vector>

#include <Windows.h>
#include <combaseapi.h>
#include <netfw.h>

#include "FwDiagnose.h"

#include "FirewallRules.h"
#include "WfpCounters.h"
#include "WfpEvents.h"

#include <wil/registry.h>
#include <wil/resource.h>

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

static bool g_removeWfpCalloutFilters = false;
bool RemoveWfpCalloutFiltersEnabled() noexcept
{
	return g_removeWfpCalloutFilters;
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
        "  -analyze-app-package-rules: Analyzes Firewall rules referencing app-packages\n"
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
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-analyze-wfp") == 0; });
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
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-remove-callouts") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		// remove-callouts will automatically enable wfp output
		g_wfpOutput = true;
		g_removeWfpCalloutFilters = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-list-app-packages") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-list-app-packages") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		LoadAllAppPackages();
		PrintAllAppPackages();
		return 0;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-analyze-app-package-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _stricmp(lhs, "-analyze-app-package-rules") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		LoadAllAppPackages();
		LoadFirewallRules();
		AnalyzeFirewallRulesReferencingAppPackages();
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
		ProcessFirewallRules();
	}

	if (WfpOutputEnabled())
	{
		OutputWfpDetails();
	}

	if (RemoveWfpCalloutFiltersEnabled())
	{
		TemporarilyRemoveWfpCalloutFilters();
	}

	if (g_wfpEventEnumeration)
	{
		ListenForWfpNetEvents();
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



/*
 * Code for enumerating existing NetEvents in a time range


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
