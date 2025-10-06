#include <algorithm>
#include <string>
#include <vector>

#include <windows.h>
#include <fwpmu.h>

#include "WfpCounters.h"

#include <wil/stl.h>
#include <wil/resource.h>

static std::vector<SubLayerDetails> g_all_sublayers;

// additional internal sublayers
constexpr GUID IPXLAT_WFP_OUTBOUND_IPV4_SUBLAYER =
{ 0xd3e70856, 0xfc90, 0x4c0a, {0xb9, 0xb2, 0xa6, 0xf7, 0x3e, 0x20, 0xb5, 0xcc} };
constexpr GUID IPXLAT_WFP_INBOUND_IPV6_SUBLAYER =
{ 0xdfb035ca, 0xc2a7, 0x4684, {0x97, 0xb6, 0x4d, 0xbc, 0x57, 0xc6, 0x35, 0x90} };
constexpr GUID IPXLAT_WFP_FORWARD_IPV4_SUBLAYER =
{ 0x4351e497, 0x5d8b, 0x46bc, {0x86, 0xd9, 0xab, 0xcc, 0xdb, 0x86, 0x8d, 0x6d} };
constexpr GUID IPXLAT_WFP_OUTBOUND_ETHERNET_SUBLAYER =
{ 0x7ea20fed, 0x30e, 0x4db0, {0x85, 0xf9, 0x23, 0x4f, 0x9a, 0xf5, 0xab, 0x50} };
constexpr GUID FWPM_SUBLAYER_EDGE_TRAVERSAL_TEREDO_AUTHORIZATION =
{ 0x7b6b11f6, 0xcbb5, 0x433c, {0xae, 0x06, 0x6a, 0x4f, 0x00, 0x76, 0xe4, 0x9e} };
constexpr GUID MPSSVC_IPSEC_MM_RULE_SUBLAYER = // the constant MMRuleSublayerGuid in the firewall codebase
{ 0x9ba30013, 0xc84e, 0x47e5, {0xac, 0x6e, 0x1e, 0x1a, 0xed, 0x72, 0xfa, 0x69} };

const GUID BuiltInSublayers[] = {
	FWPM_SUBLAYER_RPC_AUDIT,
	FWPM_SUBLAYER_IPSEC_TUNNEL,
	FWPM_SUBLAYER_UNIVERSAL,
	FWPM_SUBLAYER_LIPS,
	FWPM_SUBLAYER_SECURE_SOCKET,
	FWPM_SUBLAYER_TCP_CHIMNEY_OFFLOAD,
	FWPM_SUBLAYER_INSPECTION,
	FWPM_SUBLAYER_EDGE_TRAVERSAL, // previously called FWPM_SUBLAYER_TEREDO
	FWPM_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL,
	FWPM_SUBLAYER_IPSEC_DOSP,
	FWPM_SUBLAYER_TCP_TEMPLATES,
	FWPM_SUBLAYER_IPSEC_SECURITY_REALM,
	FWPM_SUBLAYER_MPSSVC_WSH,
	FWPM_SUBLAYER_MPSSVC_WF,
	FWPM_SUBLAYER_MPSSVC_QUARANTINE,
	FWPM_SUBLAYER_MPSSVC_EDP,
	FWPM_SUBLAYER_MPSSVC_TENANT_RESTRICTIONS,
	FWPM_SUBLAYER_MPSSVC_APP_ISOLATION,
	IPXLAT_WFP_OUTBOUND_IPV4_SUBLAYER,
	IPXLAT_WFP_INBOUND_IPV6_SUBLAYER,
	IPXLAT_WFP_FORWARD_IPV4_SUBLAYER,
	IPXLAT_WFP_OUTBOUND_ETHERNET_SUBLAYER,
	FWPM_SUBLAYER_EDGE_TRAVERSAL_TEREDO_AUTHORIZATION,
	MPSSVC_IPSEC_MM_RULE_SUBLAYER
};

static PCWSTR BuiltInSublayerToString(const GUID& guid) noexcept
{
	if (guid == FWPM_SUBLAYER_RPC_AUDIT)
	{
		return L"FWPM_SUBLAYER_RPC_AUDIT";
	}
	if (guid == FWPM_SUBLAYER_IPSEC_TUNNEL)
	{
		return L"FWPM_SUBLAYER_IPSEC_TUNNEL";
	}
	if (guid == FWPM_SUBLAYER_UNIVERSAL)
	{
		return L"FWPM_SUBLAYER_UNIVERSAL";
	}
	if (guid == FWPM_SUBLAYER_LIPS)
	{
		return L"FWPM_SUBLAYER_LIPS";
	}
	if (guid == FWPM_SUBLAYER_SECURE_SOCKET)
	{
		return L"FWPM_SUBLAYER_SECURE_SOCKET";
	}
	if (guid == FWPM_SUBLAYER_TCP_CHIMNEY_OFFLOAD)
	{
		return L"FWPM_SUBLAYER_TCP_CHIMNEY_OFFLOAD";
	}
	if (guid == FWPM_SUBLAYER_INSPECTION)
	{
		return L"FWPM_SUBLAYER_INSPECTION";
	}
	if (guid == FWPM_SUBLAYER_EDGE_TRAVERSAL)
	{
		return L"FWPM_SUBLAYER_EDGE_TRAVERSAL";
	}
	if (guid == FWPM_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL)
	{
		return L"FWPM_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL";
	}
	if (guid == FWPM_SUBLAYER_IPSEC_DOSP)
	{
		return L"FWPM_SUBLAYER_IPSEC_DOSP";
	}
	if (guid == FWPM_SUBLAYER_TCP_TEMPLATES)
	{
		return L"FWPM_SUBLAYER_TCP_TEMPLATES";
	}
	if (guid == FWPM_SUBLAYER_IPSEC_SECURITY_REALM)
	{
		return L"FWPM_SUBLAYER_IPSEC_SECURITY_REALM";
	}
	if (guid == FWPM_SUBLAYER_MPSSVC_WSH)
	{
		return L"FWPM_SUBLAYER_MPSSVC_WSH";
	}
	if (guid == FWPM_SUBLAYER_MPSSVC_WF)
	{
		return L"FWPM_SUBLAYER_MPSSVC_WF";
	}
	if (guid == FWPM_SUBLAYER_MPSSVC_QUARANTINE)
	{
		return L"FWPM_SUBLAYER_MPSSVC_QUARANTINE";
	}
	if (guid == FWPM_SUBLAYER_MPSSVC_EDP)
	{
		return L"FWPM_SUBLAYER_MPSSVC_EDP";
	}
	if (guid == FWPM_SUBLAYER_MPSSVC_TENANT_RESTRICTIONS)
	{
		return L"FWPM_SUBLAYER_MPSSVC_TENANT_RESTRICTIONS";
	}
	if (guid == FWPM_SUBLAYER_MPSSVC_APP_ISOLATION)
	{
		return L"FWPM_SUBLAYER_MPSSVC_APP_ISOLATION";
	}
	if (guid == IPXLAT_WFP_OUTBOUND_IPV4_SUBLAYER)
	{
		return L"IPXLAT_WFP_OUTBOUND_IPV4_SUBLAYER";
	}
	if (guid == IPXLAT_WFP_INBOUND_IPV6_SUBLAYER)
	{
		return L"IPXLAT_WFP_INBOUND_IPV6_SUBLAYER";
	}
	if (guid == IPXLAT_WFP_FORWARD_IPV4_SUBLAYER)
	{
		return L"IPXLAT_WFP_FORWARD_IPV4_SUBLAYER";
	}
	if (guid == IPXLAT_WFP_OUTBOUND_ETHERNET_SUBLAYER)
	{
		return L"IPXLAT_WFP_OUTBOUND_ETHERNET_SUBLAYER";
	}
	if (guid == FWPM_SUBLAYER_EDGE_TRAVERSAL_TEREDO_AUTHORIZATION)
	{
		return L"FWPM_SUBLAYER_EDGE_TRAVERSAL_TEREDO_AUTHORIZATION";
	}
	if (guid == MPSSVC_IPSEC_MM_RULE_SUBLAYER)
	{
		return L"MPSSVC_IPSEC_MM_RULE_SUBLAYER";
	}

	FAIL_FAST();
}

std::wstring SublayerToString(const SubLayerDetails& sublayer)
{
	if (std::ranges::find(BuiltInSublayers, sublayer.subLayerKey) != std::end(BuiltInSublayers))
	{
		if (sublayer.displayName == sublayer.description)
		{
			return wil::str_printf<std::wstring>(
				L"%ls : [%04x] %ls (%ls)",
				GuidToString(sublayer.subLayerKey).c_str(),
				sublayer.weight,
				BuiltInSublayerToString(sublayer.subLayerKey),
				sublayer.displayName.empty() ? L"no display name or description" : sublayer.displayName.c_str());
		}

		if (!sublayer.description.empty())
		{
			return wil::str_printf<std::wstring>(
				L"%ls : [%04x] %ls (%ls) [%ls]",
				GuidToString(sublayer.subLayerKey).c_str(),
				sublayer.weight,
				BuiltInSublayerToString(sublayer.subLayerKey),
				sublayer.displayName.empty() ? L"no display name" : sublayer.displayName.c_str(),
				sublayer.description.empty() ? L"no description" : sublayer.description.c_str());
		}
		return wil::str_printf<std::wstring>(
			L"%ls : [%04x] %ls (%ls)",
			GuidToString(sublayer.subLayerKey).c_str(),
			sublayer.weight,
			BuiltInSublayerToString(sublayer.subLayerKey),
			sublayer.displayName.empty() ? L"no display name" : sublayer.displayName.c_str());
	}

	if (sublayer.displayName == sublayer.description)
	{
		return wil::str_printf<std::wstring>(
			L"%ls : [%04x] %ls",
			GuidToString(sublayer.subLayerKey).c_str(),
			sublayer.weight,
			sublayer.displayName.empty() ? L"[no display name or description]" : sublayer.displayName.c_str());
	}

	if (!sublayer.description.empty())
	{
		return wil::str_printf<std::wstring>(
			L"%ls : [%04x] %ls (%ls)",
			GuidToString(sublayer.subLayerKey).c_str(),
			sublayer.weight,
			sublayer.displayName.c_str(),
			sublayer.description.c_str());
	}
	return wil::str_printf<std::wstring>(
		L"%ls : [%04x] %ls",
		GuidToString(sublayer.subLayerKey).c_str(),
		sublayer.weight,
		sublayer.displayName.c_str());
}

const std::vector<SubLayerDetails>& ReadWfpSubLayers() noexcept
try
{
	g_all_sublayers.clear();

	HANDLE fpwm_handle = GetFwpmEngineHandle();
	HANDLE enumHandle{};
	auto fwpm_error = FwpmSubLayerCreateEnumHandle0(fpwm_handle, nullptr, &enumHandle);
	if (fwpm_error != ERROR_SUCCESS)
	{
		std::printf("*** FwpmSubLayerCreateEnumHandle0 failed: %lu\n", fwpm_error);
		THROW_WIN32(fwpm_error);
	}
	const auto close_enum_handle = wil::scope_exit(
		[&]
		{
			FwpmSubLayerDestroyEnumHandle0(fpwm_handle, enumHandle);
		});

	for (;;)
	{
		FWPM_SUBLAYER0** entries{};
		constexpr UINT32 entries_quested = 100;
		UINT32 numEntriesReturned{};
		fwpm_error = FwpmSubLayerEnum0(fpwm_handle, enumHandle, entries_quested, &entries, &numEntriesReturned);
		if (fwpm_error != ERROR_SUCCESS)
		{
			std::printf("*** FwpmSubLayerEnum0 failed: %lu\n", fwpm_error);
			THROW_WIN32(fwpm_error);
		}
		const auto free_sublayer_entries = wil::scope_exit(
			[&]
			{
				FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
			});

		for (UINT32 i = 0; i < numEntriesReturned; ++i)
		{
			const auto* current_fwpm_filter = entries[i];
			g_all_sublayers.push_back(
				SubLayerDetails{
					.subLayerKey = current_fwpm_filter->subLayerKey,
					.displayName = current_fwpm_filter->displayData.name ? current_fwpm_filter->displayData.name : L"",
					.description = current_fwpm_filter->displayData.description ?
									   current_fwpm_filter->displayData.description :
									   L"",
					.weight = current_fwpm_filter->weight,
					.is_third_party_sublayer = std::ranges::find(
						BuiltInSublayers, current_fwpm_filter->subLayerKey) == std::end(BuiltInSublayers)
				});

		}

		if (numEntriesReturned < entries_quested)
		{
			break;
		}
	}

	std::ranges::sort(
		g_all_sublayers, [](const SubLayerDetails& left, const SubLayerDetails& right)
		{
			return left.weight > right.weight;
		});

	return g_all_sublayers;
}
catch (const std::exception& e)
{
	std::printf("*** Exception occurred while reading sublayers : %hs\n", e.what());
	return g_all_sublayers;
}

SubLayerDetails& FindSublayer(const GUID& subLayerKey)
{
	const auto found_sublayer = std::ranges::find(
		g_all_sublayers, subLayerKey, &SubLayerDetails::subLayerKey);
	if (found_sublayer != g_all_sublayers.end())
	{
		return *found_sublayer;
	}
	THROW_WIN32(ERROR_NOT_FOUND);
}

void PrintSublayerFilterDetails()
{
	// sort by filter counts, then print the details
	std::ranges::sort(g_all_sublayers, [](const SubLayerDetails& left, const SubLayerDetails& right)
		{
			return (left.filterCount + left.disabledFilterCount + left.persistentFilterCount) > (right.filterCount + right.disabledFilterCount + right.persistentFilterCount);
		});

	for (const auto& sublayer : g_all_sublayers)
	{
		if (sublayer.filterCount + sublayer.disabledFilterCount + sublayer.persistentFilterCount == 0)
		{
			continue;
		}

		if (std::ranges::find(BuiltInSublayers, sublayer.subLayerKey) != std::end(BuiltInSublayers))
		{
			std::printf(
				"    %ls : [%zu] %ls (disabled filters: %zu, persistent filters: %zu)\n",
				GuidToString(sublayer.subLayerKey).c_str(),
				sublayer.filterCount,
				BuiltInSublayerToString(sublayer.subLayerKey),
				sublayer.disabledFilterCount,
				sublayer.persistentFilterCount);
		}
		else
		{
			std::printf(
				"    %ls : [%zu] %ls (disabled: %zu, persistent: %zu)\n",
				GuidToString(sublayer.subLayerKey).c_str(),
				sublayer.filterCount,
				sublayer.displayName.c_str(),
				sublayer.disabledFilterCount,
				sublayer.persistentFilterCount);
		}
	}
}