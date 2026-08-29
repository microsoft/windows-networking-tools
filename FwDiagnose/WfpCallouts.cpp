// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <string>
#include <windows.h>
#include <fwpmu.h>
#include <aclapi.h>
#include <thread>
#include <vector>

#include "WfpCounters.h"

#include "ctEtwReader.hpp"
#include "ctEtwRecord.hpp"

#include <wil/stl.h>
#include <wil/resource.h>


static std::vector<CalloutDetails> g_all_callouts;

static wil::unique_event g_callouts_loaded_event{ wil::EventOptions::ManualReset };

// Firewall defined a number of built-in callouts
// most are by well-known GUIDs
// the 'FirewallPlumber' callouts are defined by a common GUID with
// the last two bytes defining the type and layer

static std::wstring FirewallPlumberCalloutKey(const GUID& guid)
{
	/*
		// The last two bytes are FW_PLUMBER_CALLOUT_TYPE and FWPS_LAYER_xxx.

		extern const __declspec(selectany) GUID FW_PLUMBER_CALLOUT_KEY = {
			0xc3dbed20, 0x0bb6, 0x4bf3, {0x82, 0x8d, 0x96, 0x73, 0x2e, 0x1e, 0x00, 0x00}};
		#define SET_FW_PLUMBER_CALLOUT_KEY_TYPE(Key, Type) ((Key).Data4[6] = (BYTE)(Type))
		#define SET_FW_PLUMBER_CALLOUT_KEY_LAYER(Key, LayerId) ((Key).Data4[7] = (BYTE)(LayerId))
		#define SIZE_OF_FW_PLUMBER_CALLOUT_KEY (sizeof(GUID) - 2)

		typedef enum _FW_PLUMBER_CALLOUT_TYPE
		{
			FW_PLUMBER_CALLOUT_QUERY_USER,
			FW_PLUMBER_CALLOUT_LOGGING,
			FW_PLUMBER_CALLOUT_SECONDARY_CONNECTIONS,
			FW_PLUMBER_CALLOUT_FLOW_ESTABLISHED,
			FW_PLUMBER_CALLOUT_STREAM_FLOW_ANALYSIS,
			FW_PLUMBER_NUM_CALLOUTS
		} FW_PLUMBER_CALLOUT_TYPE
	*/

	constexpr GUID FW_PLUMBER_CALLOUT_KEY =
	{.Data1 = 0xc3dbed20, .Data2 = 0x0bb6, .Data3 = 0x4bf3, .Data4 = {0x82, 0x8d, 0x96, 0x73, 0x2e, 0x1e, 0x00, 0x00} };

	if (0 != memcmp(&guid, &FW_PLUMBER_CALLOUT_KEY, sizeof(GUID) - 2))
	{
		return {};
	}

	switch (guid.Data4[6])
	{
	case 0:
		return L"FW_PLUMBER_CALLOUT_QUERY_USER";
	case 1:
		return L"FW_PLUMBER_CALLOUT_LOGGING";
	case 2:
		return L"FW_PLUMBER_CALLOUT_SECONDARY_CONNECTIONS";
	case 3:
		return L"FW_PLUMBER_CALLOUT_FLOW_ESTABLISHED";
	case 4:
		return L"FW_PLUMBER_CALLOUT_STREAM_FLOW_ANALYSIS";
	}
	FAIL_FAST();
}

// in code, NduAleFlowEstablishedV4Callout
constexpr GUID NDU_ALE_FLOW_ESTABLISHED_V4_CALLOUT =
{.Data1 = 0x8e44982b, .Data2 = 0xf477, .Data3 = 0x11df, .Data4 = {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduAleFlowEstablishedV6Callout
constexpr GUID NDU_ALE_FLOW_ESTABLISHED_V6_CALLOUT =
{.Data1 = 0x8e44982d, .Data2 = 0xf477, .Data3 = 0x11df, .Data4 = {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduInboundTransportCallout
constexpr GUID NDU_INBOUND_TRANSPORT_CALLOUT =
{.Data1 = 0x8e44982f, .Data2 = 0xf477, .Data3 = 0x11df, .Data4 = {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduOutboundTransportCallout
constexpr GUID NDU_OUTBOUND_TRANSPORT_CALLOUT =
{.Data1 = 0x8e449833, .Data2 = 0xf477, .Data3 = 0x11df, .Data4 = {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduInboundMacFrameNativeCallout
constexpr GUID NDU_INBOUND_MAC_FRAME_NATIVE_CALLOUT =
{.Data1 = 0x8e449837, .Data2 = 0xf477, .Data3 = 0x11df, .Data4 = {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduOutboundMacFrameNativeCallout
constexpr GUID NDU_OUTBOUND_MAC_FRAME_NATIVE_CALLOUT =
{.Data1 = 0x8e449839, .Data2 = 0xf477, .Data3 = 0x11df, .Data4 = {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };

// WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V4 =
{.Data1 = 0xb793d570, .Data2 = 0x34fe, .Data3 = 0x4e65, .Data4 = {0xaa, 0x76, 0x69, 0x39, 0x13, 0x83, 0xbd, 0xf8} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V6 =
{.Data1 = 0x3243c9f9, .Data2 = 0xe8a9, .Data3 = 0x4b52, .Data4 = {0xaf, 0x02, 0x07, 0x1d, 0x54, 0xec, 0x02, 0xb2} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V4 =
{.Data1 = 0x4bd1bcd6, .Data2 = 0x6ca5, .Data3 = 0x44fd, .Data4 = {0x85, 0x02, 0x90, 0x2a, 0x52, 0x45, 0xcd, 0x1b} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V6 =
{.Data1 = 0xd554fb83, .Data2 = 0x3e4d, .Data3 = 0x4ef5, .Data4 = {0x99, 0xf2, 0xb4, 0x57, 0x38, 0xad, 0xfc, 0x84} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V4 =
{.Data1 = 0xc75077d6, .Data2 = 0x5f8a, .Data3 = 0x43d8, .Data4 = {0xb9, 0x8d, 0x5a, 0xf8, 0xb2, 0x54, 0xc7, 0x88} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V6 =
{.Data1 = 0x1a9dd7db, .Data2 = 0x7bce, .Data3 = 0x4d44, .Data4 = {0xb8, 0xe7, 0x08, 0x75, 0xfc, 0x52, 0xa4, 0xa3} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V4 =
{.Data1 = 0x61b2bb46, .Data2 = 0x962b, .Data3 = 0x4832, .Data4 = {0x87, 0x1c, 0x4e, 0x68, 0x09, 0x88, 0x27, 0x33} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V6 =
{.Data1 = 0x05f90aaa, .Data2 = 0x3356, .Data3 = 0x415e, .Data4 = {0x99, 0xb9, 0x9d, 0xa6, 0x9f, 0x81, 0xfe, 0x56} };

// SetBindIntfCalloutV4 in the mpssvc code
constexpr GUID MPSSVC_INTERFACE_BINDING_CALLOUT_V4 =
{.Data1 = 0x8bc14e84, .Data2 = 0x4287, .Data3 = 0x4c9e, .Data4 = {0x81, 0xda, 0x53, 0x23, 0x35, 0x53, 0x20, 0x58} };
// SetBindIntfCalloutV6 in the mpssvc code
constexpr GUID MPSSVC_INTERFACE_BINDING_CALLOUT_V6 = {.Data1 = 0x8bc14e84, .Data2 = 0x4287, .Data3 = 0x4c9e, .Data4 = {0x81, 0xda, 0x53, 0x23, 0x35, 0x53, 0x20, 0x59} };


constexpr GUID IPXLAT_WFP_OUTBOUND_IPV4_LAYER_CALLOUT =
{.Data1 = 0x66d52657, .Data2 = 0x1979, .Data3 = 0x4e58, .Data4 = {0xb3, 0xf7, 0x47, 0x56, 0x43, 0x4c, 0x48, 0x80} };
constexpr GUID IPXLAT_WFP_INBOUND_IPV6_LAYER_CALLOUT =
{.Data1 = 0x93bb703d, .Data2 = 0x502, .Data3 = 0x42e2, .Data4 = {0x8e, 0x30, 0xa1, 0x45, 0x76, 0xe5, 0x8, 0x5d} };
constexpr GUID IPXLAT_WFP_FORWARD_IPV4_LAYER_CALLOUT =
{.Data1 = 0xb255c296, .Data2 = 0x7e0c, .Data3 = 0x4115, .Data4 = {0x95, 0xf3, 0xb7, 0xf2, 0x4a, 0x8a, 0x11, 0x62} };
constexpr GUID IPXLAT_WFP_OUTBOUND_ETHERNET_LAYER_CALLOUT =
{.Data1 = 0x26b02cd9, .Data2 = 0xc5b0, .Data3 = 0x47f0, .Data4 = {0xaf, 0x88, 0x6a, 0x20, 0x1c, 0x54, 0x60, 0x79} };

#define FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V4 FWPM_CALLOUT_BUILT_IN_RESERVED_1
#define FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V6 FWPM_CALLOUT_BUILT_IN_RESERVED_2
#define FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V4 FWPM_CALLOUT_BUILT_IN_RESERVED_3
#define FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V6 FWPM_CALLOUT_BUILT_IN_RESERVED_4
const GUID BuiltInCallouts[] =
{
	FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4,
	FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V6,
	FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4,
	FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6,
	FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V4,
	FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V6,
	FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4,
	FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6,
	FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4,
	FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6,
	FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4,
	FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6,
	FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4,
	FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6,
	FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4,
	FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6,
	FWPM_CALLOUT_IPSEC_ALE_CONNECT_V4,
	FWPM_CALLOUT_IPSEC_ALE_CONNECT_V6,
	FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V6,
	FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V4,
	FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP,
	FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP,
	FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4,
	FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6,
	FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4,
	FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6,
	FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4,
	FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6,
	FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4,
	FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6,
	FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4,
	FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6,
	FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V6, // was FWPM_CALLOUT_TEREDO_ALE_RESOURCE_ASSIGNMENT_V6,
	FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4,
	FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V6, // was FWPM_CALLOUT_TEREDO_ALE_LISTEN_V6,
	FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4,
	FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4,
	FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6,
	FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4,
	FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6,
	FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V4,
	FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V6,
	FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V4,
	FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V6,
	FWPM_CALLOUT_HTTP_TEMPLATE_SSL_HANDSHAKE,
	FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V4,
	FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V6,
	FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V4, // created in HNS - defined as FWPM_CALLOUT_BUILT_IN_RESERVED_1,
	FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V6, // FWPM_CALLOUT_BUILT_IN_RESERVED_2
	FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V4, // created in HNS - defined as FWPM_CALLOUT_BUILT_IN_RESERVED_3,
	FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V6, // defined as FWPM_CALLOUT_BUILT_IN_RESERVED_4
	IPXLAT_WFP_OUTBOUND_IPV4_LAYER_CALLOUT,
	IPXLAT_WFP_INBOUND_IPV6_LAYER_CALLOUT,
	IPXLAT_WFP_FORWARD_IPV4_LAYER_CALLOUT,
	IPXLAT_WFP_OUTBOUND_ETHERNET_LAYER_CALLOUT,
	NDU_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
	NDU_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
	NDU_INBOUND_TRANSPORT_CALLOUT,
	NDU_OUTBOUND_TRANSPORT_CALLOUT,
	NDU_INBOUND_MAC_FRAME_NATIVE_CALLOUT,
	NDU_OUTBOUND_MAC_FRAME_NATIVE_CALLOUT,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V4,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V6,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V4,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V6,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V4,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V6,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V4,
	WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V6,
	MPSSVC_INTERFACE_BINDING_CALLOUT_V4,
	MPSSVC_INTERFACE_BINDING_CALLOUT_V6,
};

static PCWSTR BuiltInCalloutsToString(const GUID& guid) noexcept;

std::wstring GetInternalCalloutString(const CalloutDetails& callout)
{
	if (std::ranges::find(BuiltInCallouts, callout.callout_key) != std::end(BuiltInCallouts))
	{
		return BuiltInCalloutsToString(callout.callout_key);
	}

	return FirewallPlumberCalloutKey(callout.callout_key);
}
std::wstring PrintCallout(const CalloutDetails& callout)
{
	const std::wstring callout_key_string = GetInternalCalloutString(callout);

	if (!callout_key_string.empty())
	{
		return wil::str_printf<std::wstring>(
			L"%ls : %ls (name : %ls)",
			GuidToString(callout.callout_key).c_str(),
			callout_key_string.c_str(),
			callout.name.empty() ? L"no name" : callout.name.c_str());
	}

	return wil::str_printf<std::wstring>(
		L"%ls : %ls",
		GuidToString(callout.callout_key).c_str(),
		callout.name.empty() ? L"(no name)" : callout.name.c_str());
}

std::wstring PrintCallout(const GUID& calloutKey)
{
	auto found_callout = std::ranges::find_if(
		std::as_const(g_all_callouts),
		[&](const CalloutDetails& callout)
		{
			return callout.callout_key == calloutKey;
		});

	if (found_callout == g_all_callouts.cend())
	{
		// refresh callouts and try again
		ReadWfpCallouts();
		found_callout = std::ranges::find_if(
			std::as_const(g_all_callouts),
			[&](const CalloutDetails& callout)
			{
				return callout.callout_key == calloutKey;
			});
	}

	if (found_callout != g_all_callouts.cend())
	{
		return PrintCallout(*found_callout);
	}

	return wil::str_printf<std::wstring>(
		L"%ls : (unknown callout)",
		GuidToString(calloutKey).c_str());

}

std::vector<CalloutDetails>& ReadWfpCallouts() noexcept
{
	return g_all_callouts;
}

const std::vector<CalloutDetails>& SortCalloutsByFilterCounts()
{
	// resort callouts by # of filters referencing them
	std::ranges::sort(
		g_all_callouts,
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

	return g_all_callouts;
}

void WriteWfpCallouts() noexcept
{
	std::printf(
		"\n"
		"**************************************************************************************\n"
		"                                     WFP Callouts                                     \n"
		"**************************************************************************************\n");
	std::printf(
		"  * Total callouts: %zu\n"
		"  * Total 3rd party callouts: %zd\n",
		g_all_callouts.size(),
		std::ranges::count_if(
			g_all_callouts, [](const CalloutDetails& callout)
			{
				return callout.is_third_party_callout;
			}));
	for (const auto& callout : g_all_callouts)
	{
		if (callout.is_third_party_callout)
		{
			std::printf("       %ls [callout id: %u] [%ls]\n",
				callout.name.empty() ? L"(no name)" : callout.name.c_str(),
				callout.callout_id,
				callout.driver_name.empty() ? L"(hidden)" : callout.driver_name.c_str());
		}
	}

	if (VerboseOutputEnabled())
	{
		GUID current_layer_being_printed{};
		for (const auto& callout : g_all_callouts)
		{
			if (current_layer_being_printed != callout.applicable_layer)
			{
				current_layer_being_printed = callout.applicable_layer;
				std::printf("\n    %hs\n", callout.layer.c_str());
			}

			std::printf("      %ls\n", PrintCallout(callout).c_str());
		}
	}
}

void LoadWfpCallouts() noexcept
try
{
	g_all_callouts.clear();

	HANDLE engine_handle = GetFwpmEngineHandle();
	HANDLE enum_handle{};
	auto fwpm_error = FwpmCalloutCreateEnumHandle0(engine_handle, nullptr, &enum_handle);
	if (fwpm_error != ERROR_SUCCESS)
	{
		std::printf("*** FwpmCalloutCreateEnumHandle0 failed: %lu\n", fwpm_error);
		THROW_WIN32(fwpm_error);
	}
	const auto close_enum_handle = wil::scope_exit(
		[&]
		{
			FwpmCalloutDestroyEnumHandle0(engine_handle, enum_handle);
		});

	for (;;)
	{
		FWPM_CALLOUT0** entries{};
		constexpr UINT32 entries_quested = 100;
		UINT32 numEntriesReturned{};

		fwpm_error = FwpmCalloutEnum0(engine_handle, enum_handle, entries_quested, &entries, &numEntriesReturned);
		if (fwpm_error != ERROR_SUCCESS)
		{
			std::printf("*** FwpmCalloutEnum0 failed: %lu\n", fwpm_error);
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
			g_all_callouts.push_back(
				CalloutDetails{
					.callout_key = current_fwpm_filter->calloutKey,
					.applicable_layer = current_fwpm_filter->applicableLayer,
					.callout_id = current_fwpm_filter->calloutId,
					.layer = FwpmLayerToString(current_fwpm_filter->applicableLayer),
					.name = current_fwpm_filter->displayData.name ?
						current_fwpm_filter->displayData.name :
						L"(no name)",
					.description = current_fwpm_filter->displayData.description ?
					   current_fwpm_filter->displayData.description :
					   L"(no description)",
				});
		}

		if (numEntriesReturned < entries_quested)
		{
			break;
		}
	}

	for (auto& callout : g_all_callouts)
	{
		if (std::ranges::find(BuiltInCallouts, callout.callout_key) != std::end(BuiltInCallouts))
		{
			continue;
		}

		if (auto callout_key_string = FirewallPlumberCalloutKey(callout.callout_key); !callout_key_string.empty())
		{
			continue;
		}

		callout.is_third_party_callout = true;
	}

	std::ranges::sort(
		g_all_callouts, [](const CalloutDetails& left, const CalloutDetails& right)
		{
			return SortedLayerRelativePriority(left.applicable_layer) < SortedLayerRelativePriority(right.applicable_layer);
		});

	// Microsoft.Windows.Networking.WFP.Callout
	static struct CalloutRundownDetails
	{
		struct CalloutDetails
		{
			std::wstring driver_name{};
			uint32_t callout_id{};
			uint32_t applicable_layer_id{};
			uint32_t behavior_flags{};
		};
		std::vector<CalloutDetails> callouts{};
	} callout_rundown_details;

	const auto callback_fn = [](const EVENT_RECORD* pRecord) {
		// Process the ETW event record
		const auto event_message = ctl::ctEtwRecord(pRecord);

		bool is_callout_rundown_record = true;
		std::wstring callout_id_key;
		is_callout_rundown_record &= event_message.queryEventProperty(L"CalloutId", callout_id_key);
		std::wstring driver_name_key;
		is_callout_rundown_record &= event_message.queryEventProperty(L"DriverName", driver_name_key);
		std::wstring applicable_layer_id_key;
		is_callout_rundown_record &= event_message.queryEventProperty(L"ApplicableLayerId", applicable_layer_id_key);
		std::wstring behavior_flags_key;
		is_callout_rundown_record &= event_message.queryEventProperty(L"BehaviorFlags", behavior_flags_key);
		if (!is_callout_rundown_record)
		{
			return;
		}

		CalloutRundownDetails::CalloutDetails new_callout_details{};
		new_callout_details.driver_name = driver_name_key;
		new_callout_details.callout_id = std::stoul(callout_id_key);
		new_callout_details.applicable_layer_id = std::stoul(applicable_layer_id_key);
		new_callout_details.behavior_flags = std::stoul(behavior_flags_key);
		callout_rundown_details.callouts.push_back(new_callout_details);
		};

	ctl::ctEtwReader etw_reader{ callback_fn };

	constexpr GUID wfpCalloutEtwProvider{.Data1 = 0x00e7ee66, .Data2 = 0x5b24, .Data3 = 0x5c41, .Data4 = {0x22,0xcb,0xaf,0x98,0xf6,0x3e,0x2f,0x90} };
	THROW_IF_FAILED(etw_reader.StartTraceSession(L"FwDiagnose", nullptr, wfpCalloutEtwProvider));
	THROW_IF_FAILED(etw_reader.EnableTraceProviders({ wfpCalloutEtwProvider }));

	const auto start_time = GetTickCount64();
	while (GetTickCount64() - start_time < 1000)
	{
		THROW_IF_FAILED(etw_reader.FlushTraceSession());
		Sleep(250);
	}
	etw_reader.StopTraceSession();

	// move the driver names into the callout details
	for (auto& callout : callout_rundown_details.callouts)
	{
		const auto found_callout = std::ranges::find_if(
			g_all_callouts,
			[&](const CalloutDetails& callout_details)
			{
				return callout_details.callout_id == callout.callout_id;
			});
		if (found_callout != g_all_callouts.end())
		{
			found_callout->driver_name = std::move(callout.driver_name);
		}
	}
}
catch (const std::exception& e)
{
	std::printf("*** Exception occurred while reading callouts : %hs\n", e.what());
}

static PCWSTR BuiltInCalloutsToString(const GUID& guid) noexcept
{
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_ALE_CONNECT_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_ALE_CONNECT_V4";
	}
	if (guid == FWPM_CALLOUT_IPSEC_ALE_CONNECT_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_ALE_CONNECT_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V6)
	{
		return L"FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V6";
	}
	if (guid == FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V4)
	{
		return L"FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V4";
	}
	if (guid == FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP)
	{
		return L"FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP";
	}
	if (guid == FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP)
	{
		return L"FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP";
	}
	if (guid == FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V6)
	{
		return L"FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V6";
	}
	if (guid == FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4)
	{
		return L"FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4";
	}
	if (guid == FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V6)
	{
		return L"FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V6";
	}
	if (guid == FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4)
	{
		return L"FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4";
	}
	if (guid == FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_HTTP_TEMPLATE_SSL_HANDSHAKE)
	{
		return L"FWPM_CALLOUT_HTTP_TEMPLATE_SSL_HANDSHAKE";
	}
	if (guid == FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V4)
	{
		return L"FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V6)
	{
		return L"FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_PROXY_CONNECTION_ACCEPT_REDIRECT_LAYER_V6";
	}
	if (guid == FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V4)
	{
		return L"FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V4";
	}
	if (guid == FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V6)
	{
		return L"FWPM_CALLOUT_ACCEPT_REDIRECT_PROXY_TAG_CONNECT_LAYER_V6";
	}
	if (guid == IPXLAT_WFP_OUTBOUND_IPV4_LAYER_CALLOUT)
	{
		return L"IPXLAT_WFP_OUTBOUND_IPV4_LAYER_CALLOUT";
	}
	if (guid == IPXLAT_WFP_INBOUND_IPV6_LAYER_CALLOUT)
	{
		return L"IPXLAT_WFP_INBOUND_IPV6_LAYER_CALLOUT";
	}
	if (guid == IPXLAT_WFP_FORWARD_IPV4_LAYER_CALLOUT)
	{
		return L"IPXLAT_WFP_FORWARD_IPV4_LAYER_CALLOUT";
	}
	if (guid == IPXLAT_WFP_OUTBOUND_ETHERNET_LAYER_CALLOUT)
	{
		return L"IPXLAT_WFP_OUTBOUND_ETHERNET_LAYER_CALLOUT";
	}
	if (guid == NDU_ALE_FLOW_ESTABLISHED_V4_CALLOUT)
	{
		return L"NDU_ALE_FLOW_ESTABLISHED_V4_CALLOUT";
	}
	if (guid == NDU_ALE_FLOW_ESTABLISHED_V6_CALLOUT)
	{
		return L"NDU_ALE_FLOW_ESTABLISHED_V6_CALLOUT";
	}
	if (guid == NDU_INBOUND_TRANSPORT_CALLOUT)
	{
		return L"NDU_INBOUND_TRANSPORT_CALLOUT";
	}
	if (guid == NDU_OUTBOUND_TRANSPORT_CALLOUT)
	{
		return L"NDU_OUTBOUND_TRANSPORT_CALLOUT";
	}
	if (guid == NDU_INBOUND_MAC_FRAME_NATIVE_CALLOUT)
	{
		return L"NDU_INBOUND_MAC_FRAME_NATIVE_CALLOUT";
	}
	if (guid == NDU_OUTBOUND_MAC_FRAME_NATIVE_CALLOUT)
	{
		return L"NDU_OUTBOUND_MAC_FRAME_NATIVE_CALLOUT";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V4)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V4";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V6)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V6";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V4)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V4";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V6)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V6";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V4)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V4";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V6)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V6";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V4)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V4";
	}
	if (guid == WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V6)
	{
		return L"WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V6";
	}
	if (guid == MPSSVC_INTERFACE_BINDING_CALLOUT_V4)
	{
		return L"MPSSVC_INTERFACE_BINDING_CALLOUT_V4";
	}
	if (guid == MPSSVC_INTERFACE_BINDING_CALLOUT_V6)
	{
		return L"MPSSVC_INTERFACE_BINDING_CALLOUT_V6";
	}
	FAIL_FAST();
}

// Attempts to take ownership of a WFP filter by setting its security information
// using the current user's SID and granting full control
// Returns ERROR_SUCCESS on success, or the error code on failure
static DWORD TakeOwnershipOfWfpFilter(_In_ const GUID& filterKey)
{
	// Get the current process token
	wil::unique_handle processToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken))
	{
		const auto error = GetLastError();
		std::printf("TakeOwnershipOfWfpFilter: OpenProcessToken failed: 0x%lx\n", error);
		return error;
	}

	// Get the token user information (contains the user's SID)
	DWORD tokenUserSize = 0;
	GetTokenInformation(processToken.get(), TokenUser, nullptr, 0, &tokenUserSize);
	if (tokenUserSize == 0)
	{
		const auto error = GetLastError();
		std::printf("TakeOwnershipOfWfpFilter: GetTokenInformation (size query) failed: 0x%lx\n", error);
		return error;
	}

	std::vector<BYTE> tokenUserBuffer(tokenUserSize);
	if (!GetTokenInformation(processToken.get(), TokenUser, tokenUserBuffer.data(), tokenUserSize, &tokenUserSize))
	{
		const auto error = GetLastError();
		std::printf("TakeOwnershipOfWfpFilter: GetTokenInformation failed: 0x%lx\n", error);
		return error;
	}

	const auto* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenUserBuffer.data());
	const PSID userSid = tokenUser->User.Sid;

	// Create a DACL that grants full control to the current user
	EXPLICIT_ACCESS_W explicitAccess{};
	explicitAccess.grfAccessPermissions = WRITE_OWNER | WRITE_DAC;
	explicitAccess.grfAccessMode = SET_ACCESS;
	explicitAccess.grfInheritance = NO_INHERITANCE;
	explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_USER;
	explicitAccess.Trustee.ptstrName = static_cast<LPWSTR>(userSid);

	wil::unique_hlocal_ptr<ACL> newDacl;
	PACL rawDacl = nullptr;
	const auto setEntriesResult = SetEntriesInAclW(1, &explicitAccess, nullptr, &rawDacl);
	if (setEntriesResult != ERROR_SUCCESS)
	{
		std::printf("TakeOwnershipOfWfpFilter: SetEntriesInAclW failed: 0x%lx\n", setEntriesResult);
		return setEntriesResult;
	}
	newDacl.reset(rawDacl);
	rawDacl = nullptr; // ownership transferred to newDacl

	// Set the owner and DACL on the filter
	constexpr SECURITY_INFORMATION securityInfo = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
	const auto setSecurityError = FwpmFilterSetSecurityInfoByKey0(
		GetFwpmEngineHandle(),
		&filterKey,
		securityInfo,
		static_cast<const SID*>(userSid),
		nullptr,  // group SID not needed for ownership
		newDacl.get(),
		nullptr); // SACL not needed for ownership

	if (setSecurityError != ERROR_SUCCESS)
	{
		if (setSecurityError == ERROR_PRIVILEGE_NOT_HELD)
		{
			std::printf("TakeOwnershipOfWfpFilter: FwpmFilterSetSecurityInfoByKey0 failed with ERROR_PRIVILEGE_NOT_HELD\n");
		}
		else if (setSecurityError == ERROR_ACCESS_DENIED)
		{
			std::printf("TakeOwnershipOfWfpFilter: FwpmFilterSetSecurityInfoByKey0 failed with ERROR_ACCESS_DENIED\n");
		}
		else
		{
			std::printf("TakeOwnershipOfWfpFilter: FwpmFilterSetSecurityInfoByKey0 failed: 0x%lx\n", setSecurityError);
		}
	}

	return setSecurityError;
}

struct RemovedFilterDetails
{
	RemovedFilterDetails(FWPM_FILTER* input_filter, PSECURITY_DESCRIPTOR input_filter_sd)
		: filter(input_filter), filter_sd(input_filter_sd)
	{
	}
	FWPM_FILTER* filter{};
	PSECURITY_DESCRIPTOR filter_sd{};
};
static std::vector<RemovedFilterDetails> g_deletedWfpFilters;
static void RestoreDeletedFilters() noexcept
{
	if (g_deletedWfpFilters.empty())
	{
		std::printf("No WFP filters were deleted - no filters to restore\n");
		return;
	}

	uint32_t failed_filters_restored = 0;

	auto* const engine_handle = GetFwpmEngineHandle();
	for (auto& [filter, filter_sd] : g_deletedWfpFilters)
	{
		if (filter)
		{
			const auto fwpm_error = FwpmFilterAdd0(
				engine_handle,
				filter,
				filter_sd,
				nullptr);
			if (fwpm_error != ERROR_SUCCESS)
			{
				// Fwpm* functions can return both Win32 errors and HRESULT values
				// investigate these specific error cases
				if (static_cast<HRESULT>(fwpm_error) == FWP_E_PROVIDER_CONTEXT_NOT_FOUND)
				{
					++failed_filters_restored;

					// see if we can find that context
					FWPM_PROVIDER_CONTEXT* provider_context{};
					const auto provider_context_error = FwpmProviderContextGetByKey(engine_handle, &filter->providerContextKey, &provider_context);
					if (provider_context_error != ERROR_SUCCESS)
					{
						std::printf("Failed to retrieve provider context for filter %llu (provider GUID %ls). Error: 0x%lx\n", filter->filterId, GuidToString(filter->providerContextKey).c_str(), provider_context_error);
					}
					else
					{
						std::printf("Provider context for filter %llu (provider GUID %ls) was found - even though FWP_E_PROVIDER_CONTEXT_NOT_FOUND was returned from FwpmFilterAdd",
							filter->filterId,
							GuidToString(filter->providerContextKey).c_str());
					}
				}
				else if (static_cast<HRESULT>(fwpm_error) == FWP_E_WRONG_SESSION)
				{
					++failed_filters_restored;
					std::printf(
						"\nFWP_E_WRONG_SESSION was returned when trying to restore filter %llu.\n"
						" This may indicate that the filter was originally added in a different session that is still active.\n"
						" Attempting to investigate active sessions to find the correct session for this filter...\n", filter->filterId);

					// enumerate sessions to see if the session is still active
					HANDLE enumHandle{};
					const auto session_enum_create_error = FwpmSessionCreateEnumHandle(engine_handle, nullptr, &enumHandle);
					if (session_enum_create_error != ERROR_SUCCESS)
					{
						std::printf("   - Failed to create session enum handle (0x%lx) to investigate FWP_E_WRONG_SESSION error for filter %llu\n", session_enum_create_error, filter->filterId);
						continue;
					}

					FWPM_SESSION0** sessions{};
					const auto free_sessions = wil::scope_exit([&] {
						if (sessions)
						{
							FwpmFreeMemory(reinterpret_cast<void**>(&sessions));
						}
						});
					UINT32 num_sessions{};
					const auto session_enum_error = FwpmSessionEnum0(engine_handle, enumHandle, 1000, &sessions, &num_sessions);
					if (session_enum_error != ERROR_SUCCESS)
					{
						std::printf("   - Failed to enumerate sessions to investigate FWP_E_WRONG_SESSION error for filter %llu. Error: 0x%lx\n", filter->filterId, session_enum_error);
						continue;
					}

					std::printf("   - Enumerated %u sessions to investigate FWP_E_WRONG_SESSION error for filter %llu:\n", num_sessions, filter->filterId);
					for (UINT32 i = 0; i < num_sessions; ++i)
					{
						const auto& session = sessions[i];
						std::printf(
							"   - Trying to restore the filters with this session %u: %hs mode, userName=%ls, displayName=%ls\n",
							i,
							!!session->kernelMode ? "kernel" : "user",
							session->username ? session->username : L"(no userName)",
							session->displayData.name ? session->displayData.name : L"(no displayName)");

						HANDLE engineHandleForSession{};
						const auto delete_engine_handle = wil::scope_exit([&] {
							if (engineHandleForSession)
							{
								FwpmEngineClose0(engineHandleForSession);
							}
							});
						const auto fwpm_engine_open_error = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, session, &engineHandleForSession);
						if (fwpm_engine_open_error != ERROR_SUCCESS)
						{
							std::printf("   - Failed to restore deleted WFP filter %llu using session %u. FwpmEngineOpen error: 0x%lx\n", filter->filterId, i, fwpm_engine_open_error);
							continue;
						}

						const auto fwpm_error_for_session = FwpmFilterAdd0(
							engineHandleForSession,
							filter,
							filter_sd,
							nullptr);
						if (fwpm_error_for_session != ERROR_SUCCESS)
						{
							std::printf("   - Failed to restore deleted WFP filter %llu using session %u. FwpmFilterAdd error: 0x%lx\n", filter->filterId, i, fwpm_error_for_session);
							continue;
						}

						std::printf("   - Successfully restored deleted WFP filter %llu using session %u\n", filter->filterId, i);
						--failed_filters_restored;
						break;
					}
					FwpmSessionDestroyEnumHandle(engine_handle, enumHandle);
				}
				else
				{
					++failed_filters_restored;
					std::printf("Failed to restore deleted WFP filter %llu. Error: 0x%lx\n", filter->filterId, fwpm_error);
				}
			}
			else
			{
				std::printf("Successfully restored deleted WFP filter %llu\n", filter->filterId);
			}

			FwpmFreeMemory(reinterpret_cast<void**>(&filter));
			FwpmFreeMemory(&filter_sd);
		}
		else
		{
			std::printf("   * Invalid filter (null FWPM_FILTER*) for a deleted filter - cannot restore this filter\n");
		}
	}
	g_deletedWfpFilters.clear();

	if (failed_filters_restored > 0)
	{
		std::printf(
			"\n*** There were some filters for callout drivers that failed to be restored.\n"
			"    The callout drivers likely prevented others from manipulating their filters.\n"
			"\n"
			"*** IT IS HIGHLY RECOMMENDED TO REBOOT AS SOON AS POSSIBLE ***\n");
	}
}

void TemporarilyRemoveWfpCalloutFilters()
try
{
	std::printf(
		"\n"
		"**************************************************************************************\n"
		"               Temporarily Remove Filters for 3rd Party WFP Callouts                  \n"
		"**************************************************************************************\n");
	const auto& specific_callout_driver = RemoveCalloutDriverName();
	const auto normalized_specific_callout_driver = NormalizedString::Create(specific_callout_driver);

	struct CalloutNames
	{
		NormalizedString driver_name;
		std::vector<NormalizedString> callout_names;
	};
	std::vector<CalloutNames> callout_drivers;
	for (const auto& callout : g_all_callouts)
	{
		if (callout.is_third_party_callout)
		{
			auto normalized_driver_name = NormalizedString::Create(callout.driver_name);

			if (!specific_callout_driver.empty())
			{
				if (!NormalizedString::StrStrComparison(normalized_driver_name, normalized_specific_callout_driver))
				{
					continue;
				}
			}

			const auto existing_entry = std::ranges::find_if(callout_drivers, [&](const auto& lhs) { return lhs.driver_name == normalized_driver_name; });
			if (existing_entry != callout_drivers.end())
			{
				// add the callout name to the existing entry for this driver
				auto normalized_callout_name = NormalizedString::Create(callout.name);
				if (std::ranges::find(existing_entry->callout_names, normalized_callout_name) == existing_entry->callout_names.end())
				{
					existing_entry->callout_names.emplace_back(std::move(normalized_callout_name));
				}
			}
			else
			{
				auto& insertion = callout_drivers.emplace_back(std::move(normalized_driver_name));
				insertion.callout_names.emplace_back(NormalizedString::Create(callout.name));
			}
		}
	}

	if (callout_drivers.empty())
	{
		std::printf("  * No 3rd party callout drivers found to remove\n");
		return;
	}

	std::printf("The following 3rd party drivers were found - associated with the listed callouts\n");
	for (const auto& callout_entry : callout_drivers)
	{
		std::printf("  * %ls\n", callout_entry.driver_name.value.c_str());
		for (const auto& callout_name : callout_entry.callout_names)
		{
			std::printf("      - %ls\n", callout_name.value.c_str());
		}
	}
	std::printf("\n");

	for (const auto& callout_entry : callout_drivers)
	{
		if (specific_callout_driver.empty())
		{
			const auto deletionPrompt = wil::str_printf<std::wstring>(L"Temporarily delete all filters referencing the callout driver '%ls'", callout_entry.driver_name.value.c_str());
			constexpr bool onlyAllowYesOrNo = true;
			if (PromptForDeletion(deletionPrompt.c_str(), onlyAllowYesOrNo) == PromptResponse::No)
			{
				continue;
			}
		}

		for (const auto& callout : g_all_callouts)
		{
			if (!callout.is_third_party_callout)
			{
				continue;
			}
			if (callout.referenced_by_filter_count_enabled + callout.referenced_by_filter_count_disabled == 0)
			{
				continue;
			}
			if (!NormalizedString::StrStrComparison(callout_entry.driver_name, NormalizedString::Create(callout.driver_name)))
			{
				continue;
			}

			std::printf(
				"\n"
				"    * Temporarily deleting the filters for WFP callout %ls - registered with driver %ls\n"
				"       Callout id %u\n"
				"       Filter count for this callout id for this driver: %llu\n",
				callout.name.c_str(),
				callout.driver_name.c_str(),
				callout.callout_id,
				callout.referenced_by_filter_count_enabled + callout.referenced_by_filter_count_disabled);

			for (const auto& current_fwpm_filter : ReadWfpFilters())
			{
				if (current_fwpm_filter.InvokesCallout(callout.callout_key))
				{
					std::printf("         Temporarily deleting filter id %llu : [filter name: %ls] [layer: %hs]\n",
						current_fwpm_filter.filterId,
						current_fwpm_filter.name.value.c_str(),
						FwpmLayerToString(current_fwpm_filter.layerKey).c_str());

					// ensure we have space in our vector before deleting the filter
					g_deletedWfpFilters.reserve(g_deletedWfpFilters.size() + 1);
					FWPM_FILTER* deleted_filter{};
					const auto filter_get_error = FwpmFilterGetByKey(GetFwpmEngineHandle(), &current_fwpm_filter.filterKey, &deleted_filter);
					if (filter_get_error != 0)
					{
						std::printf("         - FwpmFilterGetByKey failed: 0x%lx -- cannot delete filter %llu\n", filter_get_error, current_fwpm_filter.filterId);
						continue;
					}

					auto free_filter_on_failure = wil::scope_exit([&] {
						if (deleted_filter)
						{
							FwpmFreeMemory(reinterpret_cast<void**>(&deleted_filter));
						}
						});

					// take ownership of the WFP filter so we can get the SECURITY_DESCRIPTOR
					const auto ownership_error = TakeOwnershipOfWfpFilter(current_fwpm_filter.filterKey);
					if (ownership_error != ERROR_SUCCESS)
					{
						std::printf("         - TakeOwnershipOfWfpFilter failed: 0x%lx -- cannot delete filter %llu\n", ownership_error, current_fwpm_filter.filterId);
						continue;
					}

					PSID owner_sid{};
					PSID group_sid{};
					PACL dacl{};
					PACL sacl{};
					PSECURITY_DESCRIPTOR filter_security_descriptor{};
					constexpr SECURITY_INFORMATION getFilterSecurityInfo{};
					const auto get_security_error = FwpmFilterGetSecurityInfoByKey0(
						GetFwpmEngineHandle(),
						&current_fwpm_filter.filterKey,
						getFilterSecurityInfo,
						&owner_sid,
						&group_sid,
						&dacl,
						&sacl,
						&filter_security_descriptor);
					if (get_security_error != 0)
					{
						if (get_security_error == ERROR_PRIVILEGE_NOT_HELD)
						{
							std::printf("         - FwpmFilterGetSecurityInfoByKey0 failed with ERROR_PRIVILEGE_NOT_HELD -- cannot delete filter %llu\n", current_fwpm_filter.filterId);
						}
						else
						{
							std::printf("         - FwpmFilterGetSecurityInfoByKey0 failed: 0x%lx -- cannot delete filter %llu\n", get_security_error, current_fwpm_filter.filterId);
						}
						continue;
					}

					auto free_filter_security_descriptor_on_failure = wil::scope_exit([&] {
						if (filter_security_descriptor)
						{
							FwpmFreeMemory(&filter_security_descriptor);
						}
						});

					const auto delete_error = FwpmFilterDeleteByKey(GetFwpmEngineHandle(), &current_fwpm_filter.filterKey);
					if (delete_error != 0)
					{
						std::printf("         - FwpmFilterDeleteByKey failed: 0x%lx\n", delete_error);
						continue;
					}

					FWPM_FILTER* verify_deleted_filter{};
					const auto verify_filter_get_error = FwpmFilterGetByKey(GetFwpmEngineHandle(), &current_fwpm_filter.filterKey, &verify_deleted_filter);
					if (verify_filter_get_error == 0)
					{
						FwpmFreeMemory(reinterpret_cast<void**>(&verify_deleted_filter));
						std::printf("         - found the filter after FwpmFilterDeleteByKey succeeded -- cannot delete the filter (it likely applied security privileges to its filter)\n");
						continue;
					}

					g_deletedWfpFilters.emplace_back(deleted_filter, filter_security_descriptor);
					std::printf("         - Successfully deleted filter %llu (stored to restore later)\n", current_fwpm_filter.filterId);

					// successfully moved pointers to g_deletedWfpFilters, so release the scope guard's ownership of the filter memory
					free_filter_on_failure.release();
					free_filter_security_descriptor_on_failure.release();
				}
			}
		}
	}

	if (g_deletedWfpFilters.empty())
	{
		std::printf("\n * No filters were found to be removed\n");
		return;
	}

	std::printf("\n * temporarily removed %zu filters\n", g_deletedWfpFilters.size());

	// work hard to guarantee we restore the filters we deleted
	SetConsoleCtrlHandler([](DWORD) -> BOOL
		{
			std::printf("\n * Restoring filters to callout drivers...\n");
			RestoreDeletedFilters();
			TerminateProcess(GetCurrentProcess(), 0);
			return TRUE;
		},
		TRUE);

	const auto cmd_prompt_thread = CreateThread(
		nullptr,
		0,
		[](LPVOID) -> DWORD
		{
			std::printf("\n\n --- Press Enter to restore filters to callout drivers ---\n");
			std::wstring userInput;
			std::getline(std::wcin, userInput);
			g_callouts_loaded_event.SetEvent();
			return 0;
		},
		nullptr,
		0,
		nullptr);
	FAIL_FAST_IF_MSG(!cmd_prompt_thread, "Failed to create command prompt thread to wait for user input. Error: 0x%lx\n", GetLastError());

	// open the named event if another FwDiagnose instance will signal us to restore the filters
	const wil::unique_event named_event{ CreateEventW(nullptr, TRUE, FALSE, GetNamedEventForRestoringFilters()) };
	if (!named_event)
	{
		std::printf(" ** Failed to open event to wait for callouts loaded signal. Error: 0x%lx\n", GetLastError());
		WaitForSingleObject(g_callouts_loaded_event.get(), INFINITE);
	}
	else
	{
		const HANDLE wait_handles[]{ g_callouts_loaded_event.get(), named_event.get() };
		WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
	}

	std::printf("\n * Restoring filters to callout drivers...\n");
	RestoreDeletedFilters();

	// we must terminate process in this path - as the thread we created might still be waiting for user input
	// and this causes the CRT to break on process exit since the thread is still running and waiting on user input
	TerminateProcess(GetCurrentProcess(), 0);
}
catch (...)
{
	std::printf("*** Exception occurred while temporarily removing WFP filters for 3rd party callouts (0x%x)\n", wil::ResultFromCaughtException());
	RestoreDeletedFilters();
}
