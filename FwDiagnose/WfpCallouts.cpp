// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <string>
#include <windows.h>
#include <fwpmu.h>
#include <vector>

#include "WfpCounters.h"

#include "ctEtwReader.hpp"
#include "ctEtwRecord.hpp"

#include <wil/stl.h>
#include <wil/resource.h>


static std::vector<CalloutDetails> g_all_callouts;

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
	{ 0xc3dbed20, 0x0bb6, 0x4bf3, {0x82, 0x8d, 0x96, 0x73, 0x2e, 0x1e, 0x00, 0x00} };

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
{ 0x8e44982b, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduAleFlowEstablishedV6Callout
constexpr GUID NDU_ALE_FLOW_ESTABLISHED_V6_CALLOUT =
{ 0x8e44982d, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduInboundTransportCallout
constexpr GUID NDU_INBOUND_TRANSPORT_CALLOUT =
{ 0x8e44982f, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduOutboundTransportCallout
constexpr GUID NDU_OUTBOUND_TRANSPORT_CALLOUT =
{ 0x8e449833, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduInboundMacFrameNativeCallout
constexpr GUID NDU_INBOUND_MAC_FRAME_NATIVE_CALLOUT =
{ 0x8e449837, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };
// in code, NduOutboundMacFrameNativeCallout
constexpr GUID NDU_OUTBOUND_MAC_FRAME_NATIVE_CALLOUT =
{ 0x8e449839, 0xf477, 0x11df, {0x85, 0xce, 0x78, 0xe7, 0xd1, 0x81, 0x01, 0x90} };

// WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V4 =
{ 0xb793d570, 0x34fe, 0x4e65, {0xaa, 0x76, 0x69, 0x39, 0x13, 0x83, 0xbd, 0xf8} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_AUTH_CONNECT_V6 =
{ 0x3243c9f9, 0xe8a9, 0x4b52, {0xaf, 0x02, 0x07, 0x1d, 0x54, 0xec, 0x02, 0xb2} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V4 =
{ 0x4bd1bcd6, 0x6ca5, 0x44fd, {0x85, 0x02, 0x90, 0x2a, 0x52, 0x45, 0xcd, 0x1b} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_RESOURCE_ASSIGNMENT_V6 =
{ 0xd554fb83, 0x3e4d, 0x4ef5, {0x99, 0xf2, 0xb4, 0x57, 0x38, 0xad, 0xfc, 0x84} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V4 =
{ 0xc75077d6, 0x5f8a, 0x43d8, {0xb9, 0x8d, 0x5a, 0xf8, 0xb2, 0x54, 0xc7, 0x88} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_FLOW_ESTABLISHED_V6 =
{ 0x1a9dd7db, 0x7bce, 0x4d44, {0xb8, 0xe7, 0x08, 0x75, 0xfc, 0x52, 0xa4, 0xa3} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V4 =
{ 0x61b2bb46, 0x962b, 0x4832, {0x87, 0x1c, 0x4e, 0x68, 0x09, 0x88, 0x27, 0x33} };
constexpr GUID WCM_NETWORK_PRIVACY_APP_PRIORITIZATION_ENDPOINT_CLOSURE_V6 =
{ 0x05f90aaa, 0x3356, 0x415e, {0x99, 0xb9, 0x9d, 0xa6, 0x9f, 0x81, 0xfe, 0x56} };

// SetBindIntfCalloutV4 in the mpssvc code
constexpr GUID MPSSVC_INTERFACE_BINDING_CALLOUT_V4 =
{ 0x8bc14e84, 0x4287, 0x4c9e, {0x81, 0xda, 0x53, 0x23, 0x35, 0x53, 0x20, 0x58} };
// SetBindIntfCalloutV6 in the mpssvc code
constexpr GUID MPSSVC_INTERFACE_BINDING_CALLOUT_V6 = { 0x8bc14e84, 0x4287, 0x4c9e, {0x81, 0xda, 0x53, 0x23, 0x35, 0x53, 0x20, 0x59} };


constexpr GUID IPXLAT_WFP_OUTBOUND_IPV4_LAYER_CALLOUT =
{ 0x66d52657, 0x1979, 0x4e58, {0xb3, 0xf7, 0x47, 0x56, 0x43, 0x4c, 0x48, 0x80} };
constexpr GUID IPXLAT_WFP_INBOUND_IPV6_LAYER_CALLOUT =
{ 0x93bb703d, 0x502, 0x42e2, {0x8e, 0x30, 0xa1, 0x45, 0x76, 0xe5, 0x8, 0x5d} };
constexpr GUID IPXLAT_WFP_FORWARD_IPV4_LAYER_CALLOUT =
{ 0xb255c296, 0x7e0c, 0x4115, {0x95, 0xf3, 0xb7, 0xf2, 0x4a, 0x8a, 0x11, 0x62} };
constexpr GUID IPXLAT_WFP_OUTBOUND_ETHERNET_LAYER_CALLOUT =
{ 0x26b02cd9, 0xc5b0, 0x47f0, {0xaf, 0x88, 0x6a, 0x20, 0x1c, 0x54, 0x60, 0x79} };

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
	auto found_callout = std::find_if(g_all_callouts.cbegin(), g_all_callouts.cend(),
		[&](const CalloutDetails& callout)
		{
			return callout.callout_key == calloutKey;
		});
	if (found_callout == g_all_callouts.cend())
	{
		// refresh callouts and try again
		ReadWfpCallouts();
		found_callout = std::find_if(g_all_callouts.cbegin(), g_all_callouts.cend(),
			[&](const CalloutDetails& callout)
			{
				return callout.callout_key == calloutKey;
			});
	}
	if (found_callout != g_all_callouts.cend())
	{
		return PrintCallout(*found_callout);
	}
	else
	{
		return wil::str_printf<std::wstring>(
			L"%ls : (unknown callout)",
			GuidToString(calloutKey).c_str());
	}
}

std::vector<CalloutDetails>& ReadWfpCallouts() noexcept
{
	return g_all_callouts;
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
					.layer = LayerToString(current_fwpm_filter->applicableLayer),
					.name = current_fwpm_filter->displayData.name ?
						current_fwpm_filter->displayData.name :
						L"(no name)",
					.description = current_fwpm_filter->displayData.description ?
					   current_fwpm_filter->displayData.description :
					   L"(no description)",
					.callout_id = current_fwpm_filter->calloutId,
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
			return SortedLayerValue(left.applicable_layer) < SortedLayerValue(right.applicable_layer);
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

	auto callback_fn = [](const EVENT_RECORD* pRecord) {
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

	constexpr GUID wfp_callout{ 0x00e7ee66,0x5b24,0x5c41, {0x22,0xcb,0xaf,0x98,0xf6,0x3e,0x2f,0x90} };
	THROW_IF_FAILED(etw_reader.StartTraceSession(L"FwDiagnose", nullptr, wfp_callout));
	THROW_IF_FAILED(etw_reader.EnableTraceProviders({ wfp_callout }));

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
