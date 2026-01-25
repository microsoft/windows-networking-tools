// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ReSharper disable CppInconsistentNaming
// ReSharper disable IdentifierTypo
#pragma once
#include <stdint.h>
#include <optional>
#include <string>
#include <vector>

#include <windows.h>
#include <objbase.h>
#include <fwpmu.h>

#include "FwDiagnose.h"

#include <wil/resource.h>

bool InitializeWfpPerfCounters() noexcept;
uint64_t ReadWfpPerfCounters();

inline std::wstring GuidToString(const GUID& guid)
{
	wchar_t buffer[39]{};
	const auto string_length = StringFromGUID2(guid, buffer, std::size(buffer));
	FAIL_FAST_IF(string_length != std::size(buffer));

	// remove trailing null when constructing the std::wstring
	std::wstring return_string;
	return_string.assign(buffer, string_length - 1);
	return return_string;
}

void OutputWfpDetails();

HANDLE GetFwpmEngineHandle();
uint32_t SortedLayerRelativePriority(const GUID& layer) noexcept;
std::string FwpmLayerToString(const GUID& layerGuid);

struct FilterDetails
{
	GUID filterKey;
	UINT64 filterId;

	GUID layerKey;
	GUID subLayerKey;

	NormalizedString name;
	std::wstring description;
	UINT32 flags;

	uint64_t weight;
	uint64_t effectiveWeight;

	std::optional<GUID> providerKey;
	std::vector<uint8_t> providerData;

	UINT32 numFilterConditions;
	std::vector<FWPM_FILTER_CONDITION0> filterConditions;

	// not deep copying filter conditions

	FWPM_ACTION0 action_type;

    [[nodiscard]] bool IsDisabled() const noexcept
	{
		return (flags & FWPM_FILTER_FLAG_DISABLED) != 0;
	}

    [[nodiscard]] bool IsPersistent() const noexcept
	{
		return (flags & FWPM_FILTER_FLAG_PERSISTENT) != 0;
	}

    [[nodiscard]] bool InvokesCallout() const noexcept
	{
		return (action_type.type & FWP_ACTION_FLAG_CALLOUT) != 0;
	}

    [[nodiscard]] bool InvokesCallout(const GUID& calloutKey) const noexcept
	{
		if ((action_type.type & FWP_ACTION_FLAG_CALLOUT) == 0)
		{
			return false;
		}
		return action_type.calloutKey == calloutKey;
	}
};

// allow searching FilterDetails by name
inline bool operator<(const FilterDetails & lhs, const NormalizedString & rhs) noexcept
{
	return lhs.name.value < rhs.value;
}
inline bool operator<(const NormalizedString& lhs, const FilterDetails& rhs) noexcept
{
	return lhs.value < rhs.name.value;
}
inline bool operator==(const FilterDetails& lhs, const NormalizedString& rhs) noexcept
{
	return lhs.name.value == rhs.value;
}
inline bool operator==(const NormalizedString& lhs, const FilterDetails& rhs) noexcept
{
	return lhs.value == rhs.name.value;
}

void LoadWfpFilters() noexcept;
const std::vector<FilterDetails>& ReadWfpFilters() noexcept;
void WriteWfpFilters() noexcept;

const std::vector<FilterDetails>& SortFilterDetailsByFilterId();
const FilterDetails& FindFilterByFilterId(UINT64 filter_id);

const std::vector<FilterDetails>& SortFilterDetailsByName();
size_t CountFiltersByName(const NormalizedString& rule_name);
size_t CountFilterConditionsByName(const NormalizedString& rule_name);

// callout support
struct CalloutDetails
{
	GUID callout_key{};
	GUID applicable_layer{};
	uint32_t callout_id{};

    std::string layer{};
	std::wstring name{};
	std::wstring description{};
	std::wstring driver_name{};

    uint64_t referenced_by_filter_count_enabled{};
    uint64_t referenced_by_filter_count_disabled{};
	bool is_third_party_callout{ false };
	bool name_is_non_ascii_string{ true };
};

void LoadWfpCallouts() noexcept;
std::vector<CalloutDetails>& ReadWfpCallouts() noexcept;
void WriteWfpCallouts() noexcept;
void WriteThirdPartyCalloutDetails() noexcept;

void TemporarilyRemoveWfpCalloutFilters();

std::wstring GetInternalCalloutString(const CalloutDetails& callout);
std::wstring PrintCallout(const CalloutDetails& callout);
std::wstring PrintCallout(const GUID& calloutKey);

// sublayer support
struct SubLayerDetails
{
	GUID subLayerKey{};
	std::wstring displayName{};
	std::wstring description{};
	size_t filterCount{};
	size_t disabledFilterCount{};
	size_t persistentFilterCount{};
	uint16_t weight{};
	bool is_third_party_sublayer{ false };
};

void LoadWfpSubLayers() noexcept;
const std::vector<SubLayerDetails>& ReadWfpSubLayers() noexcept;
void WriteWfpSubLayers() noexcept;

SubLayerDetails& FindSublayer(const GUID& subLayerKey);
std::wstring SublayerToString(const SubLayerDetails& sublayer);
std::wstring SublayerToSimpleString(const SubLayerDetails& sublayer);
void PrintSublayerFilterDetails();

// providers support
struct ProviderDetails
{
	GUID providerKey{};
	std::wstring displayName{};
	std::wstring serviceName{};
	size_t filterCount{};
	size_t disabledFilterCount{};
	size_t persistentFilterCount{};
	bool is_third_party_provider{ false };
};

void LoadWfpProviders() noexcept;
const std::vector<ProviderDetails>& ReadWfpProviders() noexcept;
void WriteWfpProviders() noexcept;

ProviderDetails& FindProvider(const GUID& providerKey);
std::wstring ProviderToString(const ProviderDetails& provider);
void PrintProviderFilterDetails();
