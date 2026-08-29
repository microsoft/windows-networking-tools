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
#include "TcpipEvents.h"
#include "WfpCounters.h"
#include "WfpEvents.h"

#include <wil/network.h>
#include <wil/registry.h>
#include <wil/resource.h>

#include "AppContainers.h"
#include "IpProperties.h"

// manually turn on debug output for lower-level debugging
static bool g_debugOutputEnabled = false;
bool DebugOutputEnabled() noexcept
{
	return g_debugOutputEnabled;
}

static bool g_verboseOutput = false;
bool VerboseOutputEnabled() noexcept
{
	return g_verboseOutput;
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

static bool g_analyzeInboundRules = false;
static bool AnalyzeInboundRulesEnabled() noexcept
{
	return g_analyzeInboundRules;
}

DEFINE_ENUM_FLAG_OPERATORS(NET_FW_PROFILE_TYPE2)

static bool g_shieldsUpPublicProfile = false;
static bool g_shieldsUpPrivateProfile = false;
static bool g_shieldsUpDomainProfile = false;
std::vector<NET_FW_PROFILE_TYPE2> GetShieldsUpProfiles() noexcept
{
	std::vector<NET_FW_PROFILE_TYPE2> enabledProfiles{};
	if (g_shieldsUpPublicProfile)
	{
		enabledProfiles.push_back(NET_FW_PROFILE2_PUBLIC);
	}
	if (g_shieldsUpPrivateProfile)
	{
		enabledProfiles.push_back(NET_FW_PROFILE2_PRIVATE);
	}
	if (g_shieldsUpDomainProfile)
	{
		enabledProfiles.push_back(NET_FW_PROFILE2_DOMAIN);
	}
	return enabledProfiles;
}

static bool g_disableShieldsEnabled = false;
bool TurnOffShieldsUpSet() noexcept
{
	return g_disableShieldsEnabled;
}
static bool g_enableShieldsUpEnabled = false;
bool TurnOnShieldsUpSet() noexcept
{
	return g_enableShieldsUpEnabled;
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

static bool g_tcpipEventEnumeration = false;
static bool TcpipEventEnumerationEnabled() noexcept
{
	return g_tcpipEventEnumeration;
}

static bool g_removeWfpCalloutFilters = false;
static std::wstring g_removeCalloutDriverName;
bool RemoveWfpCalloutFiltersEnabled() noexcept
{
	return g_removeWfpCalloutFilters;
}
const std::wstring& RemoveCalloutDriverName() noexcept
{
	return g_removeCalloutDriverName;
}

PCWSTR GetNamedEventForRestoringFilters() noexcept
{
	return L"FwDiagnoseCalloutsLoadedEvent";
}

static void PrintUsage() noexcept
{
	std::printf(
		"\n"
		"FwDiagnose.exe [options] [-verbose]\n"
		"\n"
		"  This utility provides options to analyze Windows Firewall rules and Windows Filter Platform filters.\n"
		"  It also has utility functions for:\n"
		"     - analyzing Firewall rules allowing Inbound traffic across Firewall profiles\n"
		"     - toggling the Shield's Up Windows Firewall setting (blocking all inbound connections)\n"
		"     - enumerating and analyzing Firewall rules for App-Packages\n"
		"     - listening for and writing NetEvents from WFP\n"
		"     - temporarily removing filters for 3rd party WFP callout drivers\n"
		"\n"
		"  -? : Show this help message.\n"
		"\n"
		"  -analyze-rules : Analyzes firewall rules for potential issues\n"
		"  -clean-rules   : Prompts to delete duplicate rules\n"
		"                 : Prompts to delete rules with application exes referencing non-existing files\n"
		"                 : Prompts to delete rules referencing unknown SIDs\n"
		"                 : Prompts to delete isolation rules with a SIDs referencing non-existing profiles\n"
		"\n"
		"  -analyze-inbound-rules : Summarizes active rules allowing inbound connectivity across all Firewall profiles\n"
		"\n"
		"  -enable-shields-up  : Enables the Windows Firewall 'Shields Up' feature which blocks all inbound connections\n"
		"                        By default, enables Shields Up for all profiles\n"
		"                        Optionally, specify the profile name - e.g. -enable-shields-up:Public\n"
		"  -disable-shields-up : Disables the Windows Firewall 'Shields Up' feature which blocks all inbound connections\n"
		"                        By default, disables Shields Up for all profiles\n"
		"                        Optionally, specify the profile name - e.g. -disable-shields-up:Public\n"
		"\n"
		"  -list-app-packages         : Output details of all app-container packages\n"
		"  -analyze-app-package-rules : Analyzes Firewall rules referencing app-packages\n"
		"\n"
		"  -analyze-wfp  : Output details of WFP objects (callouts, sublayers, and filters)\n"
		"                : This requires Administrator privileges\n"
		"  -wfp-events   : Listen for and print all NetEvents from WFP\n"
		"  -tcpip-events : Listen for and print TCPIP packet drop events from ETW\n"
		"\n"
		"  -remove-callouts      : Prompt to temporarily remove filters for 3rd party WFP callout drivers\n"
		"                        : By default will prompt for all drivers to be temporarily removed (unless -driver is specified)\n"
		"                        : Will restore any removed filters before this program exits\n"
		"  -driver <driver_name> : Specify the driver name for the callout removal\n"
		"                        : Can only be specified after -remove-callouts\n"
		"  -signal-restore-callouts : automatically unblocks another instance of FwDiagnose -remove-callouts\n"
		"                             that is waiting to be signaled to restore the removed callout\n"
		"\n"
		"  -verbose : Output additional verbose details of rules and WFP objects\n");
}

int __cdecl wmain(int argc, wchar_t* argv[]) try
{
	const auto wsa_startup = wil::network::WSAStartup();
	const auto coInit = wil::CoInitializeEx();

	if (argc < 2)
	{
		PrintUsage();
		return E_INVALIDARG;
	}

	std::vector<PCWSTR> args(argv + 1, argv + argc);
	if (std::ranges::find(args, L"-?") != args.end())
	{
		PrintUsage();
		return 0;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-verbose") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-verbose") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_verboseOutput = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-signal-restore-callouts") == 0; }) != args.end())
	{
		if (args.size() != 1)
		{
			std::printf("The -signal-restore-callouts option cannot be specified with any other options\n");
			PrintUsage();
			return E_INVALIDARG;
		}

		const auto restore_filters_event{ OpenEventW(EVENT_MODIFY_STATE, FALSE, GetNamedEventForRestoringFilters()) };
		if (!restore_filters_event)
		{
			std::printf("Failed to open event to signal restore of callouts. Error: 0x%lx\n", GetLastError());
			return ERROR_INTERNAL_ERROR;
		}

		SetEvent(restore_filters_event);
		std::printf("Signaled another instance of FwDiagnose to restore filters to callouts (named event: %ws)\n", GetNamedEventForRestoringFilters());
		CloseHandle(restore_filters_event);
		return 0;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-rules") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_analyzeRules = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-clean-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-clean-rules") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_cleanBrokenRules = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-wfp") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-wfp") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_wfpOutput = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-wfp-events") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-wfp-events") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_wfpEventEnumeration = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-tcpip-events") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-tcpip-events") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_tcpipEventEnumeration = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-inbound-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-inbound-rules") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_analyzeInboundRules = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_disableShieldsEnabled = true;
		g_shieldsUpPublicProfile = true;
		g_shieldsUpPrivateProfile = true;
		g_shieldsUpDomainProfile = true;
	}
	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up:private") == 0; }) != args.end())
	{
		if (g_disableShieldsEnabled)
		{
			std::printf("-disable-shields-up was already specified - cannot specify this more than once\n");
			PrintUsage();
			return E_INVALIDARG;
		}
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up:private") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_shieldsUpPrivateProfile = true;
		g_disableShieldsEnabled = true;
	}
	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up:public") == 0; }) != args.end())
	{
		if (g_disableShieldsEnabled)
		{
			std::printf("-disable-shields-up was already specified - cannot specify this more than once\n");
			PrintUsage();
			return E_INVALIDARG;
		}
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up:public") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_shieldsUpPublicProfile = true;
		g_disableShieldsEnabled = true;
	}
	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up:domain") == 0; }) != args.end())
	{
		if (g_disableShieldsEnabled)
		{
			std::printf("-disable-shields-up was already specified - cannot specify this more than once\n");
			PrintUsage();
			return E_INVALIDARG;
		}
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-disable-shields-up:domain") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_shieldsUpDomainProfile = true;
		g_disableShieldsEnabled = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_enableShieldsUpEnabled = true;
		g_shieldsUpPublicProfile = true;
		g_shieldsUpPrivateProfile = true;
		g_shieldsUpDomainProfile = true;
	}
	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up:private") == 0; }) != args.end())
	{
		if (g_enableShieldsUpEnabled)
		{
			std::printf("-enable-shields-up was already specified - cannot specify this more than once\n");
			PrintUsage();
			return E_INVALIDARG;
		}
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up:private") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_shieldsUpPrivateProfile = true;
		g_enableShieldsUpEnabled = true;
	}
	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up:public") == 0; }) != args.end())
	{
		if (g_enableShieldsUpEnabled)
		{
			std::printf("-enable-shields-up was already specified - cannot specify this more than once\n");
			PrintUsage();
			return E_INVALIDARG;
		}
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up:public") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_shieldsUpPublicProfile = true;
		g_enableShieldsUpEnabled = true;
	}
	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up:domain") == 0; }) != args.end())
	{
		if (g_enableShieldsUpEnabled)
		{
			std::printf("-enable-shields-up was already specified - cannot specify this more than once\n");
			PrintUsage();
			return E_INVALIDARG;
		}
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-enable-shields-up:domain") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_shieldsUpDomainProfile = true;
		g_enableShieldsUpEnabled = true;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-remove-callouts") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-remove-callouts") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		g_removeWfpCalloutFilters = true;

		if (auto found_driver_iter = std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-driver") == 0; }); found_driver_iter != args.end())
		{
			auto driver_name_iter = std::next(found_driver_iter);
			if (driver_name_iter != args.end())
			{
				g_removeCalloutDriverName = *driver_name_iter;
				// remove the driver name as well so that we don't have any unrecognized arguments later
				args.erase(driver_name_iter, std::next(driver_name_iter));
			}
			else
			{
				std::printf("A driver name must be specified after -driver\n");
				PrintUsage();
				return E_INVALIDARG;
			}
			std::printf("* Temporarily removing filters for callout driver: %ws\n", g_removeCalloutDriverName.c_str());

			auto removed_driver_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-driver") == 0; });
			args.erase(removed_driver_args.cbegin(), args.end());
		}
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-list-app-packages") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-list-app-packages") == 0; });
		args.erase(removed_args.cbegin(), args.end());
		LoadAllAppPackages();
		PrintAllAppPackages();
		return 0;
	}

	if (std::ranges::find_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-app-package-rules") == 0; }) != args.end())
	{
		auto removed_args = std::ranges::remove_if(args, [&](const auto* lhs) { return _wcsicmp(lhs, L"-analyze-app-package-rules") == 0; });
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
			std::printf(" %ws ", arg);
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
		UpdateCalloutsByFilterCounts();
		SortCalloutsByFilterCounts();
		SortFilterDetailsByFilterId();
		} };

	if (RemoveWfpCalloutFiltersEnabled())
	{
		wfp_thread.join();
		TemporarilyRemoveWfpCalloutFilters();
		return 0;
	}

	auto firewall_thread = std::thread{ [] { LoadFirewallRules(); } };
	auto app_package_thread = std::thread{ [] { LoadAllAppPackages(); } };
	auto network_properties_thread = std::thread{ [] { LoadIpProperties(); } };

	// joining in the order of expected time-to-complete
	// (WFP often taking a while)
	app_package_thread.join();
	firewall_thread.join();
	network_properties_thread.join();
	wfp_thread.join();

	if (AnalyzeRulesEnabled() || CleanBrokenRulesEnabled())
	{
		ProcessFirewallPolicy();
		ProcessFirewallRules();
	}

	if (AnalyzeInboundRulesEnabled())
	{
		ProcessInboundRules();
	}

	if (TurnOnShieldsUpSet() || TurnOffShieldsUpSet())
	{
		ProcessShieldsUp();
	}

	if (WfpOutputEnabled())
	{
		OutputWfpDetails();
	}

	if (WfpEventEnumerationEnabled())
	{
		ListenForWfpNetEvents();
	}

	if (TcpipEventEnumerationEnabled())
	{
		ListenForTcpipEvents();
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
