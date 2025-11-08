// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <memory>
#include <vector>

#include <Windows.h>
#include <fwpmu.h>

#include "ctPerformanceCounter.hpp"

#include "WfpCounters.h"

#include <wil/stl.h>
#include <wil/resource.h>

const static ctl::ctWmiService* g_wmi = nullptr;
static ctl::ctPerformanceCounter* g_wmi_performance = nullptr;
static std::shared_ptr<ctl::ctPerformanceCounterCounter<ULONGLONG>>* g_wfp_filter_count;

static HANDLE g_wfp_engineHandle = nullptr;
HANDLE GetFwpmEngineHandle()
{
	if (!g_wfp_engineHandle)
	{
		const auto fwpm_error = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &g_wfp_engineHandle);
		if (fwpm_error != ERROR_SUCCESS)
		{
			THROW_WIN32(fwpm_error);
		}
	}

	return g_wfp_engineHandle;
}

bool InitializeWfpPerfCounters() noexcept
try
{
	g_wmi = new ctl::ctWmiService(L"root\\cimv2");
	g_wmi_performance = new ctl::ctPerformanceCounter(*g_wmi);
	g_wfp_filter_count = new std::shared_ptr<ctl::ctPerformanceCounterCounter<ULONGLONG>>();

	*g_wfp_filter_count = ctCreatePerfCounter<ULONGLONG>(
		*g_wmi,
		ctl::ctWmiEnumClassName::WfpFilterCount,
		L"Total",
		ctl::ctPerformanceCounterCollectionType::Detailed);
	g_wmi_performance->add_counter(*g_wfp_filter_count);
	return true;
}
catch (...)
{
	return false;
}

uint64_t ReadWfpPerfCounters()
{
	g_wmi_performance->start_all_counters(1);
	Sleep(100);
	g_wmi_performance->stop_all_counters();

	auto [begin_wfp_filter_total, end_wfp_filter_total] = (*g_wfp_filter_count)->reference_range();
	const std::vector<ULONGLONG> ull_filter_count{ begin_wfp_filter_total, end_wfp_filter_total };
	return *ull_filter_count.rbegin();
}

uint32_t SortedLayerValue(const GUID& layer) noexcept
{
	uint32_t layer_priority = 0;
	// first ALE layers
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_RESOURCE_RELEASE_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_RESOURCE_RELEASE_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_LISTEN_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_LISTEN_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD)
	{
		return layer_priority;
	}

	++layer_priority;
	if (layer == FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6)
	{
		return layer_priority;
	}

	// then ale-redirect layers
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_CONNECT_REDIRECT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_CONNECT_REDIRECT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_BIND_REDIRECT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_BIND_REDIRECT_V6)
	{
		return layer_priority;
	}
	constexpr GUID FWPM_LAYER_ALE_ACCEPT_REDIRECT_V4 = { 0x29243AF8, 0xECAF, 0x4436, {0xA4, 0x4E, 0xF9, 0xFB, 0x70, 0x70, 0xAA, 0x04} };
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_ACCEPT_REDIRECT_V4)
	{
		return layer_priority;
	}
	constexpr GUID FWPM_LAYER_ALE_ACCEPT_REDIRECT_V6 = { 0xC9809347, 0x218F, 0x4B7F, {0xA7, 0x42, 0xB2, 0x81, 0xA3, 0xF6, 0x31, 0xB4} };
	++layer_priority;
	if (layer == FWPM_LAYER_ALE_ACCEPT_REDIRECT_V6)
	{
		return layer_priority;
	}

	// then stream and datagram
	++layer_priority;
	if (layer == FWPM_LAYER_STREAM_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_STREAM_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_STREAM_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_STREAM_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_DATAGRAM_DATA_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_STREAM_PACKET_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_STREAM_PACKET_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_DATAGRAM_DATA_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD)
	{
		return layer_priority;
	}

	// then transport
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_TRANSPORT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_TRANSPORT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_TRANSPORT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_TRANSPORT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD)
	{
		return layer_priority;
	}

	// then ICMP error
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_ICMP_ERROR_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_ICMP_ERROR_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD)
	{
		return layer_priority;
	}

	// the IP packet
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_IPPACKET_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_IPPACKET_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_IPPACKET_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_IPPACKET_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD)
	{
		return layer_priority;
	}

	// then IP forward
	++layer_priority;
	if (layer == FWPM_LAYER_IPFORWARD_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IPFORWARD_V4_DISCARD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IPFORWARD_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IPFORWARD_V6_DISCARD)
	{
		return layer_priority;
	}

	// then mac-frame-ethernet
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET)
	{
		return layer_priority;
	}

	// then mac-frame-native
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST)
	{
		return layer_priority;
	}

	// then vswitch-transport
	++layer_priority;
	if (layer == FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_TRANSPORT_FAST)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_TRANSPORT_FAST)
	{
		return layer_priority;
	}

	// then vswitch-ethernet
	++layer_priority;
	if (layer == FWPM_LAYER_INGRESS_VSWITCH_ETHERNET)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_EGRESS_VSWITCH_ETHERNET)
	{
		return layer_priority;
	}

	// then ipsec
	++layer_priority;
	if (layer == FWPM_LAYER_IPSEC_KM_DEMUX_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IPSEC_KM_DEMUX_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IPSEC_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IPSEC_V6)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IKEEXT_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_IKEEXT_V6)
	{
		return layer_priority;
	}

	// then rpc
	++layer_priority;
	if (layer == FWPM_LAYER_RPC_UM)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_RPC_EPMAP)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_RPC_EP_ADD)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_RPC_PROXY_CONN)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_RPC_PROXY_IF)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_KM_AUTHORIZATION)
	{
		return layer_priority;
	}

	// then name-resolution layers
	++layer_priority;
	if (layer == FWPM_LAYER_NAME_RESOLUTION_CACHE_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_NAME_RESOLUTION_CACHE_V6)
	{
		return layer_priority;
	}

	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4)
	{
		return layer_priority;
	}
	++layer_priority;
	if (layer == FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V6)
	{
		return layer_priority;
	}

	++layer_priority;
	if (layer == FWPM_LAYER_INBOUND_RESERVED2)
	{
		return layer_priority;
	}
	FAIL_FAST();
}

std::string LayerToString(const GUID& layerGuid)
{
	if (layerGuid == FWPM_LAYER_INBOUND_IPPACKET_V4)
	{
		return "FWPM_LAYER_INBOUND_IPPACKET_V4";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD)
	{
		return "FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_IPPACKET_V6)
	{
		return "FWPM_LAYER_INBOUND_IPPACKET_V6";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD)
	{
		return "FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_IPPACKET_V4)
	{
		return "FWPM_LAYER_OUTBOUND_IPPACKET_V4";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD)
	{
		return "FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_IPPACKET_V6)
	{
		return "FWPM_LAYER_OUTBOUND_IPPACKET_V6";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD)
	{
		return "FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_IPFORWARD_V4)
	{
		return "FWPM_LAYER_IPFORWARD_V4";
	}
	if (layerGuid == FWPM_LAYER_IPFORWARD_V4_DISCARD)
	{
		return "FWPM_LAYER_IPFORWARD_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_IPFORWARD_V6)
	{
		return "FWPM_LAYER_IPFORWARD_V6";
	}
	if (layerGuid == FWPM_LAYER_IPFORWARD_V6_DISCARD)
	{
		return "FWPM_LAYER_IPFORWARD_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_TRANSPORT_V4)
	{
		return "FWPM_LAYER_INBOUND_TRANSPORT_V4";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD)
	{
		return "FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_TRANSPORT_V6)
	{
		return "FWPM_LAYER_INBOUND_TRANSPORT_V6";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD)
	{
		return "FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_TRANSPORT_V4)
	{
		return "FWPM_LAYER_OUTBOUND_TRANSPORT_V4";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD)
	{
		return "FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_TRANSPORT_V6)
	{
		return "FWPM_LAYER_OUTBOUND_TRANSPORT_V6";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD)
	{
		return "FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_STREAM_V4)
	{
		return "FWPM_LAYER_STREAM_V4";
	}
	if (layerGuid == FWPM_LAYER_STREAM_V4_DISCARD)
	{
		return "FWPM_LAYER_STREAM_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_STREAM_V6)
	{
		return "FWPM_LAYER_STREAM_V6";
	}
	if (layerGuid == FWPM_LAYER_STREAM_V6_DISCARD)
	{
		return "FWPM_LAYER_STREAM_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_DATAGRAM_DATA_V4)
	{
		return "FWPM_LAYER_DATAGRAM_DATA_V4";
	}
	if (layerGuid == FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD)
	{
		return "FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_DATAGRAM_DATA_V6)
	{
		return "FWPM_LAYER_DATAGRAM_DATA_V6";
	}
	if (layerGuid == FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD)
	{
		return "FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_ICMP_ERROR_V4)
	{
		return "FWPM_LAYER_INBOUND_ICMP_ERROR_V4";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD)
	{
		return "FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_ICMP_ERROR_V6)
	{
		return "FWPM_LAYER_INBOUND_ICMP_ERROR_V6";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD)
	{
		return "FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4)
	{
		return "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD)
	{
		return "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6)
	{
		return "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD)
	{
		return "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4)
	{
		return "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD)
	{
		return "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6)
	{
		return "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD)
	{
		return "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_LISTEN_V4)
	{
		return "FWPM_LAYER_ALE_AUTH_LISTEN_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD)
	{
		return "FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_LISTEN_V6)
	{
		return "FWPM_LAYER_ALE_AUTH_LISTEN_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD)
	{
		return "FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
	{
		return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD)
	{
		return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)
	{
		return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD)
	{
		return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_CONNECT_V4)
	{
		return "FWPM_LAYER_ALE_AUTH_CONNECT_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD)
	{
		return "FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_CONNECT_V6)
	{
		return "FWPM_LAYER_ALE_AUTH_CONNECT_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD)
	{
		return "FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4)
	{
		return "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD)
	{
		return "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6)
	{
		return "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD)
	{
		return "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET)
	{
		return "FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET)
	{
		return "FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE)
	{
		return "FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE)
	{
		return "FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE";
	}
	if (layerGuid == FWPM_LAYER_INGRESS_VSWITCH_ETHERNET)
	{
		return "FWPM_LAYER_INGRESS_VSWITCH_ETHERNET";
	}
	if (layerGuid == FWPM_LAYER_EGRESS_VSWITCH_ETHERNET)
	{
		return "FWPM_LAYER_EGRESS_VSWITCH_ETHERNET";
	}
	if (layerGuid == FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V4)
	{
		return "FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V4";
	}
	if (layerGuid == FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V6)
	{
		return "FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V6";
	}
	if (layerGuid == FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V4)
	{
		return "FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V4";
	}
	if (layerGuid == FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V6)
	{
		return "FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V6";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_TRANSPORT_FAST)
	{
		return "FWPM_LAYER_INBOUND_TRANSPORT_FAST";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_TRANSPORT_FAST)
	{
		return "FWPM_LAYER_OUTBOUND_TRANSPORT_FAST";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST)
	{
		return "FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST)
	{
		return "FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST";
	}
	if (layerGuid == FWPM_LAYER_IPSEC_KM_DEMUX_V4)
	{
		return "FWPM_LAYER_IPSEC_KM_DEMUX_V4";
	}
	if (layerGuid == FWPM_LAYER_IPSEC_KM_DEMUX_V6)
	{
		return "FWPM_LAYER_IPSEC_KM_DEMUX_V6";
	}
	if (layerGuid == FWPM_LAYER_IPSEC_V4)
	{
		return "FWPM_LAYER_IPSEC_V4";
	}
	if (layerGuid == FWPM_LAYER_IPSEC_V6)
	{
		return "FWPM_LAYER_IPSEC_V6";
	}
	if (layerGuid == FWPM_LAYER_IKEEXT_V4)
	{
		return "FWPM_LAYER_IKEEXT_V4";
	}
	if (layerGuid == FWPM_LAYER_IKEEXT_V6)
	{
		return "FWPM_LAYER_IKEEXT_V6";
	}
	if (layerGuid == FWPM_LAYER_RPC_UM)
	{
		return "FWPM_LAYER_RPC_UM";
	}
	if (layerGuid == FWPM_LAYER_RPC_EPMAP)
	{
		return "FWPM_LAYER_RPC_EPMAP";
	}
	if (layerGuid == FWPM_LAYER_RPC_EP_ADD)
	{
		return "FWPM_LAYER_RPC_EP_ADD";
	}
	if (layerGuid == FWPM_LAYER_RPC_PROXY_CONN)
	{
		return "FWPM_LAYER_RPC_PROXY_CONN";
	}
	if (layerGuid == FWPM_LAYER_RPC_PROXY_IF)
	{
		return "FWPM_LAYER_RPC_PROXY_IF";
	}
	if (layerGuid == FWPM_LAYER_KM_AUTHORIZATION)
	{
		return "FWPM_LAYER_KM_AUTHORIZATION";
	}
	if (layerGuid == FWPM_LAYER_NAME_RESOLUTION_CACHE_V4)
	{
		return "FWPM_LAYER_NAME_RESOLUTION_CACHE_V4";
	}
	if (layerGuid == FWPM_LAYER_NAME_RESOLUTION_CACHE_V6)
	{
		return "FWPM_LAYER_NAME_RESOLUTION_CACHE_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_RESOURCE_RELEASE_V4)
	{
		return "FWPM_LAYER_ALE_RESOURCE_RELEASE_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_RESOURCE_RELEASE_V6)
	{
		return "FWPM_LAYER_ALE_RESOURCE_RELEASE_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4)
	{
		return "FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6)
	{
		return "FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_CONNECT_REDIRECT_V4)
	{
		return "FWPM_LAYER_ALE_CONNECT_REDIRECT_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_CONNECT_REDIRECT_V6)
	{
		return "FWPM_LAYER_ALE_CONNECT_REDIRECT_V6";
	}
	if (layerGuid == FWPM_LAYER_ALE_BIND_REDIRECT_V4)
	{
		return "FWPM_LAYER_ALE_BIND_REDIRECT_V4";
	}
	if (layerGuid == FWPM_LAYER_ALE_BIND_REDIRECT_V6)
	{
		return "FWPM_LAYER_ALE_BIND_REDIRECT_V6";
	}
	if (layerGuid == FWPM_LAYER_STREAM_PACKET_V4)
	{
		return "FWPM_LAYER_STREAM_PACKET_V4";
	}
	if (layerGuid == FWPM_LAYER_STREAM_PACKET_V6)
	{
		return "FWPM_LAYER_STREAM_PACKET_V6";
	}
	if (layerGuid == FWPM_LAYER_INBOUND_RESERVED2)
	{
		return "FWPM_LAYER_INBOUND_RESERVED2";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4)
	{
		return "FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4";
	}
	if (layerGuid == FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V6)
	{
		return "FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V6";
	}

	constexpr GUID FWPM_LAYER_ALE_ACCEPT_REDIRECT_V4 = { 0x29243AF8, 0xECAF, 0x4436, {0xA4, 0x4E, 0xF9, 0xFB, 0x70, 0x70, 0xAA, 0x04} };
	if (layerGuid == FWPM_LAYER_ALE_ACCEPT_REDIRECT_V4)
	{
		return "FWPM_LAYER_ALE_ACCEPT_REDIRECT_V4";
	}
	constexpr GUID FWPM_LAYER_ALE_ACCEPT_REDIRECT_V6 = { 0xC9809347, 0x218F, 0x4B7F, {0xA7, 0x42, 0xB2, 0x81, 0xA3, 0xF6, 0x31, 0xB4} };
	if (layerGuid == FWPM_LAYER_ALE_ACCEPT_REDIRECT_V6)
	{
		return "FWPM_LAYER_ALE_ACCEPT_REDIRECT_V6";
	}
	return "<< UNKNOWN LAYER >>";
}
