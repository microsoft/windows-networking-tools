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
