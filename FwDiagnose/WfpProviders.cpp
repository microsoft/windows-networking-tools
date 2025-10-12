// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <string>
#include <vector>

#include <windows.h>
#include <fwpmu.h>
#include "ctEtwReader.hpp"
#include "ctEtwRecord.hpp"

#include "WfpCounters.h"

#include <wil/stl.h>
#include <wil/resource.h>

static std::vector<ProviderDetails> g_all_providers;

// internal providers
constexpr GUID TEREDO_WFP_PROVIDER_GUID =
{ 0x893a4f22, 0x9bba, 0x49b7, {0x8c, 0x66, 0x3d, 0x40, 0x92, 0x9c, 0x8f, 0xd5} };
// MipsProviderGuid in code
constexpr GUID MPSSVC_IPSEC_PROVIDER = { 0x1bebc969, 0x61a5, 0x4732, {0xa1, 0x77, 0x84, 0x7a, 0x08, 0x17, 0x86, 0x2a} };
// NduWfpCalloutProviderGuid in code
constexpr GUID NDU_WFP_CALLOUT_PROVIDER =
{ 0x8e44982a, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// LipsProviderGuid in code
constexpr GUID MPSSVC_POLICY_AGENT_IPSEC_PROVIDER =
{ 0xaa6a7d87, 0x7f8f, 0x4d2a, {0xbe, 0x53, 0xfd, 0xa5, 0x55, 0xcd, 0x5f, 0xe3} };

const GUID BuiltInProviders[] = {
	FWPM_PROVIDER_MPSSVC_WSH,
	FWPM_PROVIDER_MPSSVC_WF,
	FWPM_PROVIDER_MPSSVC_EDP,
	FWPM_PROVIDER_MPSSVC_TENANT_RESTRICTIONS,
	FWPM_PROVIDER_MPSSVC_APP_ISOLATION,
	FWPM_PROVIDER_IKEEXT,
	FWPM_PROVIDER_IPSEC_DOSP_CONFIG,
	FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD,
	FWPM_PROVIDER_TCP_TEMPLATES,
	MPSSVC_IPSEC_PROVIDER,
	MPSSVC_POLICY_AGENT_IPSEC_PROVIDER,
	TEREDO_WFP_PROVIDER_GUID,
	NDU_WFP_CALLOUT_PROVIDER,
};

static PCWSTR BuiltInProvidersToString(const GUID& guid) noexcept
{
	if (guid == FWPM_PROVIDER_IKEEXT)
	{
		return L"FWPM_PROVIDER_IKEEXT";
	}
	if (guid == FWPM_PROVIDER_IPSEC_DOSP_CONFIG)
	{
		return L"FWPM_PROVIDER_IPSEC_DOSP_CONFIG";
	}
	if (guid == FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD)
	{
		return L"FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD";
	}
	if (guid == FWPM_PROVIDER_TCP_TEMPLATES)
	{
		return L"FWPM_PROVIDER_TCP_TEMPLATES";
	}
	if (guid == FWPM_PROVIDER_MPSSVC_WSH)
	{
		return L"FWPM_PROVIDER_MPSSVC_WSH";
	}
	if (guid == FWPM_PROVIDER_MPSSVC_WF)
	{
		return L"FWPM_PROVIDER_MPSSVC_WF";
	}
	if (guid == FWPM_PROVIDER_MPSSVC_EDP)
	{
		return L"FWPM_PROVIDER_MPSSVC_EDP";
	}
	if (guid == FWPM_PROVIDER_MPSSVC_TENANT_RESTRICTIONS)
	{
		return L"FWPM_PROVIDER_MPSSVC_TENANT_RESTRICTIONS";
	}
	if (guid == FWPM_PROVIDER_MPSSVC_APP_ISOLATION)
	{
		return L"FWPM_PROVIDER_MPSSVC_APP_ISOLATION";
	}
	if (guid == TEREDO_WFP_PROVIDER_GUID)
	{
		return L"TEREDO_WFP_PROVIDER_GUID";
	}
	if (guid == MPSSVC_IPSEC_PROVIDER)
	{
		return L"MPSSVC_IPSEC_PROVIDER";
	}
	if (guid == NDU_WFP_CALLOUT_PROVIDER)
	{
		return L"NDU_WFP_CALLOUT_PROVIDER";
	}
	if (guid == MPSSVC_POLICY_AGENT_IPSEC_PROVIDER)
	{
		return L"MPSSVC_POLICY_AGENT_IPSEC_PROVIDER";
	}
	FAIL_FAST();
}


std::wstring ProviderToString(const ProviderDetails& provider)
{
	if (std::ranges::find(BuiltInProviders, provider.providerKey) != std::end(BuiltInProviders))
	{
		if (!provider.serviceName.empty())
		{
			return wil::str_printf<std::wstring>(
				L"%ls [%ls] (service name %ls)",
				BuiltInProvidersToString(provider.providerKey),
				provider.displayName.c_str(),
				provider.serviceName.c_str());
		}
		return wil::str_printf<std::wstring>(
			L"%ls [%ls] (no service name)",
			BuiltInProvidersToString(provider.providerKey),
			provider.displayName.c_str());
	}

	if (!provider.serviceName.empty())
	{
		return wil::str_printf<std::wstring>(
			L"%ls (service name %ls)",
			provider.displayName.c_str(),
			provider.serviceName.c_str());
	}
	return wil::str_printf<std::wstring>(
		L"%ls (no service name)",
		provider.displayName.c_str());
}

const std::vector<ProviderDetails>& ReadWfpProviders() noexcept
try
{
	g_all_providers.clear();

	HANDLE engine_handle = GetFwpmEngineHandle();
	HANDLE enum_handle{};
	auto fwpm_error = FwpmProviderCreateEnumHandle0(engine_handle, nullptr, &enum_handle);
	if (fwpm_error != ERROR_SUCCESS)
	{
		std::printf("*** FwpmProviderCreateEnumHandle0 failed: %lu\n", fwpm_error);
		THROW_WIN32(fwpm_error);
	}
	const auto close_enum_handle = wil::scope_exit(
		[&]
		{
			FwpmProviderDestroyEnumHandle0(engine_handle, enum_handle);
		});

	for (;;)
	{
		FWPM_PROVIDER0** entries{};
		constexpr UINT32 entries_quested = 100;
		UINT32 numEntriesReturned{};
		fwpm_error = FwpmProviderEnum0(engine_handle, enum_handle, entries_quested, &entries, &numEntriesReturned);
		if (fwpm_error != ERROR_SUCCESS)
		{
			std::printf("*** FwpmProviderEnum0 failed: %lu\n", fwpm_error);
			THROW_WIN32(fwpm_error);
		}
		const auto free_Provider_entries = wil::scope_exit(
			[&]
			{
				FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
			});

		for (UINT32 i = 0; i < numEntriesReturned; ++i)
		{
			const auto* current_fwpm_filter = entries[i];
			g_all_providers.push_back(
				ProviderDetails{
					.providerKey = current_fwpm_filter->providerKey,
					.displayName = current_fwpm_filter->displayData.name ? current_fwpm_filter->displayData.name : L"",
					.serviceName = current_fwpm_filter->serviceName ? current_fwpm_filter->serviceName : L"",
					.is_third_party_provider = std::ranges::find(
						BuiltInProviders, current_fwpm_filter->providerKey) == std::end(BuiltInProviders)
				});
		}

		if (numEntriesReturned < entries_quested)
		{
			break;
		}
	}

	// sort by layer
	std::ranges::sort(
		g_all_providers, [](const ProviderDetails& left, const ProviderDetails& right)
		{
			const auto* const left_is_built_in = std::ranges::find(BuiltInProviders, left.providerKey);
			const auto* const right_is_built_in = std::ranges::find(BuiltInProviders, right.providerKey);

			// if only the left is built in, prefer the left
			if (left_is_built_in != std::end(BuiltInProviders) && right_is_built_in == std::end(BuiltInProviders))
			{
				return true;
			}
			// if only the right is built in, prefer the right
			if (left_is_built_in == std::end(BuiltInProviders) && right_is_built_in != std::end(BuiltInProviders))
			{
				return false;
			}
			// if both are built in, sort by the order in the BuiltInProviders array
			if (left_is_built_in != std::end(BuiltInProviders) && right_is_built_in != std::end(BuiltInProviders))
			{
				return left_is_built_in < right_is_built_in;
			}
			// if neither are built in, sort by service name
			if (left_is_built_in == std::end(BuiltInProviders) && right_is_built_in == std::end(BuiltInProviders))
			{
				// if neither are built in, sort by service name
				return left.displayName < right.displayName;
			}
			// should never get here
			FAIL_FAST();
		});

	// Microsoft.Windows.Networking.WFP.Callout
	constexpr GUID wfp_callout{ 0x00e7ee66,0x5b24,0x5c41, {0x22,0xcb,0xaf,0x98,0xf6,0x3e,0x2f,0x90} };

	static std::atomic<uint64_t> last_event_time = 0;
	ctl::ctEtwReader etw_reader{
		[](const EVENT_RECORD* pRecord) {
				// Process the ETW event record
				const auto event_message = ctl::ctEtwRecord(pRecord);
				wprintf(L" *** [event id %d] [keyword: %llu]: %ws\n", 
					event_message.getEventId(),
					event_message.getKeyword(),
					event_message.writeFormattedMessage(true).c_str());
				last_event_time.store(GetTickCount64());
		}
	};
	THROW_IF_FAILED(etw_reader.StartTraceSession(L"FwDiagnose", nullptr, wfp_callout));
	THROW_IF_FAILED(etw_reader.EnableTraceProviders({wfp_callout}));

	// loop until we haven't seen an event for 1/2  second
	const auto start_time = GetTickCount64();
	uint64_t last_seen_time = 0;
	while (GetTickCount64() - start_time < 1000)
	{
		const auto queried_last_event_time = last_event_time.load();
		if (last_seen_time != 0 && (queried_last_event_time - last_seen_time) > 500)
		{
			wprintf(L"\n - no events for 1/2 second, stopping ETW read\n");
			break;
		}

		last_seen_time = queried_last_event_time;
		THROW_IF_FAILED(etw_reader.FlushTraceSession());
		Sleep(100);
	}

	return g_all_providers;
}
catch (const std::exception& e)
{
	std::printf("*** Exception occurred while reading providers : %hs\n", e.what());
	return g_all_providers;
}

ProviderDetails& FindProvider(const GUID& providerKey)
{
	const auto found_provider = std::ranges::find(g_all_providers, providerKey, &ProviderDetails::providerKey);
	if (found_provider != g_all_providers.end())
	{
		return *found_provider;
	}
	THROW_WIN32(ERROR_NOT_FOUND);
}

void PrintProviderFilterDetails()
{
	// sort by filter counts, then print the details
	std::ranges::sort(g_all_providers, [](const ProviderDetails& left, const ProviderDetails& right)
		{
			return (left.filterCount + left.disabledFilterCount + left.persistentFilterCount) > (right.filterCount + right.disabledFilterCount + right.persistentFilterCount);
		});

	for (const auto& provider : g_all_providers)
	{
		if (provider.filterCount + provider.disabledFilterCount + provider.persistentFilterCount == 0)
		{
			continue;
		}

		const auto built_in_provider_string = ProviderToString(provider);
		std::printf(
			"    %ls : [%zu] %ls (disabled filters: %zu, persistent filters: %zu)\n",
			GuidToString(provider.providerKey).c_str(),
			provider.filterCount,
			built_in_provider_string.c_str(),
			provider.disabledFilterCount,
			provider.persistentFilterCount);
	}
}