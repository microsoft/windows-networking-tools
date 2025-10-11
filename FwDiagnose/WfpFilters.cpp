// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <ranges>
#include <string>
#include <vector>

#include <windows.h>
#include <fwpmu.h>

#include "WfpCounters.h"

#include <wil/stl.h>
#include <wil/resource.h>

static std::vector<FilterDetails> g_all_filters;

/*
*  Uncomment when needed for debugging
* 
static std::wstring FwpmConditionFieldToString(const GUID& fieldKey) noexcept;
*/

const std::vector<FilterDetails>& ReadWfpFilters(bool verbose_output)
{
	g_all_filters.clear();

	HANDLE engine_handle = GetFwpmEngineHandle();
	HANDLE enum_handle{};
	auto fwpm_error = FwpmFilterCreateEnumHandle0(engine_handle, nullptr, &enum_handle);
	if (fwpm_error != ERROR_SUCCESS)
	{
		if (verbose_output)
		{
			std::printf("*** FwpmFilterCreateEnumHandle0 failed: %lu\n", fwpm_error);
		}
		THROW_WIN32(fwpm_error);
	}
	const auto close_enum_handle = wil::scope_exit(
		[&]
		{
			FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
		});

	for (;;)
	{
		FWPM_FILTER0** entries{};
		constexpr UINT32 entries_quested = 100;
		UINT32 numEntriesReturned{};
		fwpm_error = FwpmFilterEnum0(engine_handle, enum_handle, entries_quested, &entries, &numEntriesReturned);
		if (fwpm_error != ERROR_SUCCESS)
		{
			if (verbose_output)
			{
				std::printf("*** FwpmFilterEnum0 failed: %lu\n", fwpm_error);
			}
			THROW_WIN32(fwpm_error);
		}
		const auto free_filter_entries = wil::scope_exit(
			[&]
			{
				FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
			});

		for (UINT32 i = 0; i < numEntriesReturned; ++i)
		{
			const auto* current_fwpm_filter = entries[i];
			g_all_filters.push_back(
				FilterDetails{
					.filterKey = current_fwpm_filter->filterKey,
					.filterId = current_fwpm_filter->filterId,
					.layerKey = current_fwpm_filter->layerKey,
					.subLayerKey = current_fwpm_filter->subLayerKey,
					.name = current_fwpm_filter->displayData.name ? NormalizedString::Normalize(current_fwpm_filter->displayData.name) : NormalizedString::Normalize(L""),
					.description = current_fwpm_filter->displayData.description ? current_fwpm_filter->displayData.description : L"",
					.flags = current_fwpm_filter->flags,
					.weight =
						current_fwpm_filter->weight.type == FWP_UINT64 ? *current_fwpm_filter->weight.uint64
						:
						current_fwpm_filter->weight.type == FWP_UINT32 ? current_fwpm_filter->weight.uint32
						:
						current_fwpm_filter->weight.type == FWP_UINT16 ? current_fwpm_filter->weight.uint16
						:
						current_fwpm_filter->weight.type == FWP_UINT8 ? current_fwpm_filter->weight.uint8
						:
						0,
					.effectiveWeight =
						current_fwpm_filter->effectiveWeight.type == FWP_UINT64 ? *current_fwpm_filter->effectiveWeight.uint64
						:
						current_fwpm_filter->effectiveWeight.type == FWP_UINT32 ? current_fwpm_filter->effectiveWeight.uint32
						:
						current_fwpm_filter->effectiveWeight.type == FWP_UINT16 ? current_fwpm_filter->effectiveWeight.uint16
						:
						current_fwpm_filter->effectiveWeight.type == FWP_UINT8 ? current_fwpm_filter->effectiveWeight.uint8
						:
						0,
					.providerKey = current_fwpm_filter->providerKey ? std::optional(*current_fwpm_filter->providerKey) : std::nullopt,
					.providerData =
						current_fwpm_filter->providerData.data ? std::vector(
							current_fwpm_filter->providerData.data,
							current_fwpm_filter->providerData.data + current_fwpm_filter->providerData.size)
						: std::vector<uint8_t>{},
					.numFilterConditions = current_fwpm_filter->numFilterConditions,
					.filterConditions = current_fwpm_filter->filterCondition ?
						std::vector(
							current_fwpm_filter->filterCondition,
							current_fwpm_filter->filterCondition + current_fwpm_filter->numFilterConditions)
						: std::vector<FWPM_FILTER_CONDITION0>{},
					.action_type = current_fwpm_filter->action,
				});

			// update sublayer details
			try
			{
				auto& sublayerDetails = FindSublayer(current_fwpm_filter->subLayerKey);
				++sublayerDetails.filterCount;
				if (current_fwpm_filter->flags & FWPM_FILTER_FLAG_DISABLED)
				{
					++sublayerDetails.disabledFilterCount;
				}
				if (current_fwpm_filter->flags & FWPM_FILTER_FLAG_PERSISTENT)
				{
					++sublayerDetails.persistentFilterCount;
				}
			}
			catch (...)
			{
				std::printf(
					"   Filter %ls in unknown sublayer %ls\n",
					current_fwpm_filter->displayData.name ? current_fwpm_filter->displayData.name : L"(no name)",
					GuidToString(current_fwpm_filter->subLayerKey).c_str());
			}

			// update provider details
			if (current_fwpm_filter->providerKey)
			{
				try
				{
					auto& providerDetails = FindProvider(*current_fwpm_filter->providerKey);
					++providerDetails.filterCount;
					if (current_fwpm_filter->flags & FWPM_FILTER_FLAG_DISABLED)
					{
						++providerDetails.disabledFilterCount;
					}
					if (current_fwpm_filter->flags & FWPM_FILTER_FLAG_PERSISTENT)
					{
						++providerDetails.persistentFilterCount;
					}
				}
				catch (...)
				{
					std::printf(
						"   Filter %ls has unknown provider %ls\n",
						current_fwpm_filter->displayData.name ? current_fwpm_filter->displayData.name : L"(no name)",
						GuidToString(*current_fwpm_filter->providerKey).c_str());
				}
			}
		}

		if (numEntriesReturned < entries_quested)
		{
			break;
		}
	}

	return g_all_filters;
}

const std::vector<FilterDetails>& SortFilterDetailsByName()
{
	std::ranges::sort(
		g_all_filters,
		[](const FilterDetails& lhs, const FilterDetails& rhs) noexcept
		{
			return lhs.name < rhs.name;
		});
	return g_all_filters;
}

size_t CountFiltersByName(const NormalizedString& rule_name)
{
	const auto lower_bound_iter = std::lower_bound(
		g_all_filters.cbegin(),
		g_all_filters.cend(),
		rule_name,
		[](const FilterDetails& lhs, const NormalizedString& rhs) noexcept
		{
			return lhs.name < rhs;
		});
	if (lower_bound_iter == g_all_filters.cend())
	{
		// there can be zero filters when a rule exists that is set to match anything
		return 0;
	}

	const auto upper_bound_iter = std::upper_bound(
		lower_bound_iter,
		g_all_filters.cend(),
		rule_name,
		[](const NormalizedString& lhs, const FilterDetails& rhs) noexcept
		{
			return lhs < rhs.name;
		});

	return static_cast<size_t>(std::distance(lower_bound_iter, upper_bound_iter));
}

size_t CountFilterConditionsByName(const NormalizedString& rule_name)
{
	const auto lower_bound_iter = std::lower_bound(
		g_all_filters.cbegin(),
		g_all_filters.cend(),
		rule_name,
		[](const FilterDetails& lhs, const NormalizedString& rhs) noexcept
		{
			return lhs.name < rhs;
		});
	if (lower_bound_iter == g_all_filters.cend())
	{
		// there can be zero filters when a rule exists that is set to match anything
		return 0;
	}

	const auto upper_bound_iter = std::upper_bound(
		lower_bound_iter,
		g_all_filters.cend(),
		rule_name,
		[](const NormalizedString& lhs, const FilterDetails& rhs) noexcept
		{
			return lhs < rhs.name;
		});

	size_t condition_count = 0;
	for (auto iter = lower_bound_iter; iter != upper_bound_iter; ++iter)
	{
		condition_count += iter->numFilterConditions;
	}
	return condition_count;
}

/*
*  Uncomment when needed for debugging
* 
std::wstring FwpmConditionFieldToString(const GUID& fieldKey) noexcept
{
	constexpr struct FwpmConditionField
	{
		const GUID& fieldKey;
		PCWSTR fieldName;
	} WfpConditions[] =
	{
		{ FWPM_CONDITION_ALE_PACKAGE_FAMILY_NAME, L"FWPM_CONDITION_ALE_PACKAGE_FAMILY_NAME" },
		{ FWPM_CONDITION_INTERFACE_MAC_ADDRESS, L"FWPM_CONDITION_INTERFACE_MAC_ADDRESS" },
		{ FWPM_CONDITION_MAC_LOCAL_ADDRESS, L"FWPM_CONDITION_MAC_LOCAL_ADDRESS" },
		{ FWPM_CONDITION_MAC_REMOTE_ADDRESS, L"FWPM_CONDITION_MAC_REMOTE_ADDRESS" },
		{ FWPM_CONDITION_ETHER_TYPE, L"FWPM_CONDITION_ETHER_TYPE" },
		{ FWPM_CONDITION_VLAN_ID, L"FWPM_CONDITION_VLAN_ID" },
		{ FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID, L"FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID" },
		{ FWPM_CONDITION_NDIS_PORT, L"FWPM_CONDITION_NDIS_PORT" },
		{ FWPM_CONDITION_NDIS_MEDIA_TYPE, L"FWPM_CONDITION_NDIS_MEDIA_TYPE" },
		{ FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE, L"FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE" },
		{ FWPM_CONDITION_L2_FLAGS, L"FWPM_CONDITION_L2_FLAGS" },
		{ FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE, L"FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE" },
		{ FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE, L"FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE" },
		{ FWPM_CONDITION_ALE_PACKAGE_ID, L"FWPM_CONDITION_ALE_PACKAGE_ID" },
		{ FWPM_CONDITION_MAC_SOURCE_ADDRESS, L"FWPM_CONDITION_MAC_SOURCE_ADDRESS" },
		{ FWPM_CONDITION_MAC_DESTINATION_ADDRESS, L"FWPM_CONDITION_MAC_DESTINATION_ADDRESS" },
		{ FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE, L"FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE" },
		{ FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE, L"FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE" },
		{ FWPM_CONDITION_IP_SOURCE_PORT, L"FWPM_CONDITION_IP_SOURCE_PORT" },
		{ FWPM_CONDITION_IP_DESTINATION_PORT, L"FWPM_CONDITION_IP_DESTINATION_PORT" },
		{ FWPM_CONDITION_VSWITCH_ID, L"FWPM_CONDITION_VSWITCH_ID" },
		{ FWPM_CONDITION_VSWITCH_NETWORK_TYPE, L"FWPM_CONDITION_VSWITCH_NETWORK_TYPE" },
		{ FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID, L"FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID" },
		{ FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID, L"FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID" },
		{ FWPM_CONDITION_VSWITCH_SOURCE_VM_ID, L"FWPM_CONDITION_VSWITCH_SOURCE_VM_ID" },
		{ FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID, L"FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID" },
		{ FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE, L"FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE" },
		{ FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE, L"FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE" },
		{ FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE, L"FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE" },
		{ FWPM_CONDITION_IPSEC_SECURITY_REALM_ID, L"FWPM_CONDITION_IPSEC_SECURITY_REALM_ID" },
		{ FWPM_CONDITION_ALE_EFFECTIVE_NAME, L"FWPM_CONDITION_ALE_EFFECTIVE_NAME" },
		{ FWPM_CONDITION_IP_LOCAL_ADDRESS, L"FWPM_CONDITION_IP_LOCAL_ADDRESS" },
		{ FWPM_CONDITION_IP_REMOTE_ADDRESS, L"FWPM_CONDITION_IP_REMOTE_ADDRESS" },
		{ FWPM_CONDITION_IP_SOURCE_ADDRESS, L"FWPM_CONDITION_IP_SOURCE_ADDRESS" },
		{ FWPM_CONDITION_IP_DESTINATION_ADDRESS, L"FWPM_CONDITION_IP_DESTINATION_ADDRESS" },
		{ FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE, L"FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE" },
		{ FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE, L"FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE" },
		{ FWPM_CONDITION_IP_NEXTHOP_ADDRESS, L"FWPM_CONDITION_IP_NEXTHOP_ADDRESS" },
		{ FWPM_CONDITION_IP_LOCAL_INTERFACE, L"FWPM_CONDITION_IP_LOCAL_INTERFACE" },
		{ FWPM_CONDITION_IP_ARRIVAL_INTERFACE, L"FWPM_CONDITION_IP_ARRIVAL_INTERFACE" },
		{ FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE, L"FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE" },
		{ FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE, L"FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE" },
		{ FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX, L"FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX" },
		{ FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX, L"FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX" },
		{ FWPM_CONDITION_IP_NEXTHOP_INTERFACE, L"FWPM_CONDITION_IP_NEXTHOP_INTERFACE" },
		{ FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE, L"FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE" },
		{ FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE, L"FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE" },
		{ FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX, L"FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX" },
		{ FWPM_CONDITION_ORIGINAL_PROFILE_ID, L"FWPM_CONDITION_ORIGINAL_PROFILE_ID" },
		{ FWPM_CONDITION_CURRENT_PROFILE_ID, L"FWPM_CONDITION_CURRENT_PROFILE_ID" },
		{ FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID, L"FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID" },
		{ FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID, L"FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID" },
		{ FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID, L"FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID" },
		{ FWPM_CONDITION_REAUTHORIZE_REASON, L"FWPM_CONDITION_REAUTHORIZE_REASON" },
		{ FWPM_CONDITION_ORIGINAL_ICMP_TYPE, L"FWPM_CONDITION_ORIGINAL_ICMP_TYPE" },
		{ FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE, L"FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE" },
		{ FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE, L"FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE" },
		{ FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH, L"FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH" },
		{ FWPM_CONDITION_INTERFACE_TYPE, L"FWPM_CONDITION_INTERFACE_TYPE" },
		{ FWPM_CONDITION_TUNNEL_TYPE, L"FWPM_CONDITION_TUNNEL_TYPE" },
		{ FWPM_CONDITION_IP_FORWARD_INTERFACE, L"FWPM_CONDITION_IP_FORWARD_INTERFACE" },
		{ FWPM_CONDITION_IP_PROTOCOL, L"FWPM_CONDITION_IP_PROTOCOL" },
		{ FWPM_CONDITION_IP_LOCAL_PORT, L"FWPM_CONDITION_IP_LOCAL_PORT" },
		{ FWPM_CONDITION_IP_REMOTE_PORT, L"FWPM_CONDITION_IP_REMOTE_PORT" },
		{ FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE, L"FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE" },
		{ FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS, L"FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS" },
		{ FWPM_CONDITION_EMBEDDED_PROTOCOL, L"FWPM_CONDITION_EMBEDDED_PROTOCOL" },
		{ FWPM_CONDITION_EMBEDDED_LOCAL_PORT, L"FWPM_CONDITION_EMBEDDED_LOCAL_PORT" },
		{ FWPM_CONDITION_EMBEDDED_REMOTE_PORT, L"FWPM_CONDITION_EMBEDDED_REMOTE_PORT" },
		{ FWPM_CONDITION_FLAGS, L"FWPM_CONDITION_FLAGS" },
		{ FWPM_CONDITION_DIRECTION, L"FWPM_CONDITION_DIRECTION" },
		{ FWPM_CONDITION_INTERFACE_INDEX, L"FWPM_CONDITION_INTERFACE_INDEX" },
		{ FWPM_CONDITION_SUB_INTERFACE_INDEX, L"FWPM_CONDITION_SUB_INTERFACE_INDEX" },
		{ FWPM_CONDITION_SOURCE_INTERFACE_INDEX, L"FWPM_CONDITION_SOURCE_INTERFACE_INDEX" },
		{ FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX, L"FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX" },
		{ FWPM_CONDITION_DESTINATION_INTERFACE_INDEX, L"FWPM_CONDITION_DESTINATION_INTERFACE_INDEX" },
		{ FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX, L"FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX" },
		{ FWPM_CONDITION_ALE_APP_ID, L"FWPM_CONDITION_ALE_APP_ID" },
		{ FWPM_CONDITION_ALE_ORIGINAL_APP_ID, L"FWPM_CONDITION_ALE_ORIGINAL_APP_ID" },
		{ FWPM_CONDITION_ALE_USER_ID, L"FWPM_CONDITION_ALE_USER_ID" },
		{ FWPM_CONDITION_ALE_REMOTE_USER_ID, L"FWPM_CONDITION_ALE_REMOTE_USER_ID" },
		{ FWPM_CONDITION_ALE_REMOTE_MACHINE_ID, L"FWPM_CONDITION_ALE_REMOTE_MACHINE_ID" },
		{ FWPM_CONDITION_ALE_PROMISCUOUS_MODE, L"FWPM_CONDITION_ALE_PROMISCUOUS_MODE" },
		{ FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT, L"FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT" },
		{ FWPM_CONDITION_ALE_REAUTH_REASON, L"FWPM_CONDITION_ALE_REAUTH_REASON" },
		{ FWPM_CONDITION_ALE_NAP_CONTEXT, L"FWPM_CONDITION_ALE_NAP_CONTEXT" },
		{ FWPM_CONDITION_KM_AUTH_NAP_CONTEXT, L"FWPM_CONDITION_KM_AUTH_NAP_CONTEXT" },
		{ FWPM_CONDITION_REMOTE_USER_TOKEN, L"FWPM_CONDITION_REMOTE_USER_TOKEN" },
		{ FWPM_CONDITION_RPC_IF_UUID, L"FWPM_CONDITION_RPC_IF_UUID" },
		{ FWPM_CONDITION_RPC_IF_VERSION, L"FWPM_CONDITION_RPC_IF_VERSION" },
		{ FWPM_CONDITION_RPC_IF_FLAG, L"FWPM_CONDITION_RPC_IF_FLAG" },
		{ FWPM_CONDITION_DCOM_APP_ID, L"FWPM_CONDITION_DCOM_APP_ID" },
		{ FWPM_CONDITION_IMAGE_NAME, L"FWPM_CONDITION_IMAGE_NAME" },
		{ FWPM_CONDITION_RPC_PROTOCOL, L"FWPM_CONDITION_RPC_PROTOCOL" },
		{ FWPM_CONDITION_RPC_AUTH_TYPE, L"FWPM_CONDITION_RPC_AUTH_TYPE" },
		{ FWPM_CONDITION_RPC_AUTH_LEVEL, L"FWPM_CONDITION_RPC_AUTH_LEVEL" },
		{ FWPM_CONDITION_SEC_ENCRYPT_ALGORITHM, L"FWPM_CONDITION_SEC_ENCRYPT_ALGORITHM" },
		{ FWPM_CONDITION_SEC_KEY_SIZE, L"FWPM_CONDITION_SEC_KEY_SIZE" },
		{ FWPM_CONDITION_IP_LOCAL_ADDRESS_V4, L"FWPM_CONDITION_IP_LOCAL_ADDRESS_V4" },
		{ FWPM_CONDITION_IP_LOCAL_ADDRESS_V6, L"FWPM_CONDITION_IP_LOCAL_ADDRESS_V6" },
		{ FWPM_CONDITION_PIPE, L"FWPM_CONDITION_PIPE" },
		{ FWPM_CONDITION_IP_REMOTE_ADDRESS_V4, L"FWPM_CONDITION_IP_REMOTE_ADDRESS_V4" },
		{ FWPM_CONDITION_IP_REMOTE_ADDRESS_V6, L"FWPM_CONDITION_IP_REMOTE_ADDRESS_V6" },
		{ FWPM_CONDITION_RPC_OPNUM, L"FWPM_CONDITION_RPC_OPNUM" },
		{ FWPM_CONDITION_PROCESS_WITH_RPC_IF_UUID, L"FWPM_CONDITION_PROCESS_WITH_RPC_IF_UUID" },
		{ FWPM_CONDITION_RPC_EP_VALUE, L"FWPM_CONDITION_RPC_EP_VALUE" },
		{ FWPM_CONDITION_RPC_EP_FLAGS, L"FWPM_CONDITION_RPC_EP_FLAGS" },
		{ FWPM_CONDITION_CLIENT_TOKEN, L"FWPM_CONDITION_CLIENT_TOKEN" },
		{ FWPM_CONDITION_RPC_SERVER_NAME, L"FWPM_CONDITION_RPC_SERVER_NAME" },
		{ FWPM_CONDITION_RPC_SERVER_PORT, L"FWPM_CONDITION_RPC_SERVER_PORT" },
		{ FWPM_CONDITION_RPC_PROXY_AUTH_TYPE, L"FWPM_CONDITION_RPC_PROXY_AUTH_TYPE" },
		{ FWPM_CONDITION_CLIENT_CERT_KEY_LENGTH, L"FWPM_CONDITION_CLIENT_CERT_KEY_LENGTH" },
		{ FWPM_CONDITION_CLIENT_CERT_OID, L"FWPM_CONDITION_CLIENT_CERT_OID" },
		{ FWPM_CONDITION_NET_EVENT_TYPE, L"FWPM_CONDITION_NET_EVENT_TYPE" },
		{ FWPM_CONDITION_PEER_NAME, L"FWPM_CONDITION_PEER_NAME" },
		{ FWPM_CONDITION_REMOTE_ID, L"FWPM_CONDITION_REMOTE_ID" },
		{ FWPM_CONDITION_AUTHENTICATION_TYPE, L"FWPM_CONDITION_AUTHENTICATION_TYPE" },
		{ FWPM_CONDITION_KM_TYPE, L"FWPM_CONDITION_KM_TYPE" },
		{ FWPM_CONDITION_KM_MODE, L"FWPM_CONDITION_KM_MODE" },
		{ FWPM_CONDITION_IPSEC_POLICY_KEY, L"FWPM_CONDITION_IPSEC_POLICY_KEY" },
		{ FWPM_CONDITION_QM_MODE, L"FWPM_CONDITION_QM_MODE" },
		{ FWPM_CONDITION_COMPARTMENT_ID, L"FWPM_CONDITION_COMPARTMENT_ID" },
		{ FWPM_CONDITION_RESERVED0, L"FWPM_CONDITION_RESERVED0" },
		{ FWPM_CONDITION_RESERVED1, L"FWPM_CONDITION_RESERVED1" },
		{ FWPM_CONDITION_RESERVED2, L"FWPM_CONDITION_RESERVED2" },
		{ FWPM_CONDITION_RESERVED3, L"FWPM_CONDITION_RESERVED3" },
		{ FWPM_CONDITION_RESERVED4, L"FWPM_CONDITION_RESERVED4" },
		{ FWPM_CONDITION_RESERVED5, L"FWPM_CONDITION_RESERVED5" },
		{ FWPM_CONDITION_RESERVED6, L"FWPM_CONDITION_RESERVED6" },
		{ FWPM_CONDITION_RESERVED7, L"FWPM_CONDITION_RESERVED7" },
		{ FWPM_CONDITION_RESERVED8, L"FWPM_CONDITION_RESERVED8" },
		{ FWPM_CONDITION_RESERVED9, L"FWPM_CONDITION_RESERVED9" },
		{ FWPM_CONDITION_RESERVED10, L"FWPM_CONDITION_RESERVED10" },
		{ FWPM_CONDITION_RESERVED11, L"FWPM_CONDITION_RESERVED11" },
		{ FWPM_CONDITION_RESERVED12, L"FWPM_CONDITION_RESERVED12" },
		{ FWPM_CONDITION_RESERVED13, L"FWPM_CONDITION_RESERVED13" },
		{ FWPM_CONDITION_RESERVED14, L"FWPM_CONDITION_RESERVED14" },
		{ FWPM_CONDITION_RESERVED15, L"FWPM_CONDITION_RESERVED15" }
	};

	// Search for the GUID in the array
	for (const auto& condition : WfpConditions)
	{
		if (condition.fieldKey == fieldKey)
		{
			return condition.fieldName;
		}
	}

	// If no match found, return the GUID as a string
	return GuidToString(fieldKey);
}
*/
