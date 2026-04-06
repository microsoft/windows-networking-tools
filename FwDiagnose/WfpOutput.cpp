// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <numeric>
#include <ranges>
#include <stdio.h>

#include <windows.h>
#include "firewall.h"
#include "WfpCounters.h"
#include "FirewallRules.h"

#include <wil/stl.h>
#include <wil/resource.h>

void OutputWfpDetails()
{
	// verify has admin access
	if (!HasFirewallAdminAccess())
	{
		std::printf("  Administrative privileges required - try running from an elevated Administrator command prompt.\n");
		THROW_WIN32(ERROR_ACCESS_DENIED);
	}

	WriteWfpCallouts();
	auto& wfp_callouts = ReadWfpCallouts();

	WriteWfpSubLayers();
	const auto& wfp_sublayers = ReadWfpSubLayers();

	WriteWfpProviders();
	// const auto& wfp_providers = ReadWfpProviders();

	WriteWfpFilters();
	const auto& filter_details = ReadWfpFilters();

	UpdateCalloutsByFilterCounts();
	SortCalloutsByFilterCounts();
	if (VerboseOutputEnabled())
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
						FwpmLayerToString(current_fwpm_filter.layerKey).c_str(),
						filter_sublayer.c_str());
				}
			}
		}
	}

	if (VerboseOutputEnabled())
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
}
