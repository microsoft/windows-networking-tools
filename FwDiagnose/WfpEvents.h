#pragma once
#include <string>
#include <fwpmu.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <mstcpip.h>
#include <Sddl.h>

#include <wil/resource.h>

inline
std::wstring
PrintNetEventType(const FWPM_NET_EVENT5* net_event)
{
	switch (net_event->type)
	{
	case FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE:
		return L"  -Type: IKEEXT_MM_FAILURE";
	case FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE:
		return L"  -Type: IKEEXT_QM_FAILURE";
	case FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE:
		return L"  -Type: IKEEXT_EM_FAILURE";
	case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
		return L"  -Type: CLASSIFY_DROP";
	case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
		return L"  -Type: IPSEC_KERNEL_DROP";
	case FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP:
		return L"  -Type: IPSEC_DOSP_DROP";
	case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
		return L"  -Type: CLASSIFY_ALLOW";
	case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
		return L"  -Type: CAPABILITY_DROP";
	case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
		return L"  -Type: CAPABILITY_ALLOW";
	case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
		return L"  -Type: CLASSIFY_DROP_MAC";
	case FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL:
		return L"  -Type: LPM_PACKET_ARRIVAL";
	case FWPM_NET_EVENT_TYPE_MAX:
	default:
		return L"  -Type: (unknown FWPM_NET_EVENT_TYPE - " + std::to_wstring(net_event->type) + L")";
	}
}

inline
std::wstring
PrintNetEventHeader(const FWPM_NET_EVENT5* net_event)
{
	std::wstring result;

	// TimeStamp
	SYSTEMTIME system_time;
	FAIL_FAST_IF_WIN32_BOOL_FALSE(FileTimeToSystemTime(&net_event->header.timeStamp, &system_time));
	SYSTEMTIME local_time;
	FAIL_FAST_IF_WIN32_BOOL_FALSE(SystemTimeToTzSpecificLocalTime(nullptr, &system_time, &local_time));

	result += L"  - TimeStamp: " +
		std::to_wstring(local_time.wMonth) + L"/" +
		std::to_wstring(local_time.wDay) + L"/" +
		std::to_wstring(local_time.wYear) + L"  " +
		std::to_wstring(local_time.wHour) + L":" +
		std::to_wstring(local_time.wMinute) + L":" +
		std::to_wstring(local_time.wSecond) + L"\n";

	result += L"    Flags: 0x" + std::to_wstring(net_event->header.flags) + L"\n";

	result += L"    IPVersion: ";
	switch (net_event->header.ipVersion)
	{
	case FWP_IP_VERSION_V4:
		result += L"IPv4";
		break;
	case FWP_IP_VERSION_V6:
		result += L"IPv6";
		break;
	case FWP_IP_VERSION_NONE:
		result += L"IP_VERSION_NONE";
		// Address Family is only set for FWP_IP_VERSION_NONE
		result += L"    AddressFamily: " + std::to_wstring(net_event->header.addressFamily);
		break;
	default:
		result += L"(unknown ipVersion - " + std::to_wstring(net_event->header.ipVersion) + L")";
		break;
	}
	result += L"\n";

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
	{
		result += L"    IPProtocol: " + std::to_wstring(net_event->header.ipProtocol) + L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET)
	{
		result += L"    LocalAddr: ";
		if (net_event->header.ipVersion == FWP_IP_VERSION_V4)
		{
			WCHAR result_buf[17]{}; // documented to be large enough for a IPv4 address string
			FAIL_FAST_IF(nullptr == RtlIpv4AddressToStringW(
				reinterpret_cast<const in_addr*>(&net_event->header.localAddrV4),
				result_buf));
			result += result_buf;
		}
		else if (net_event->header.ipVersion == FWP_IP_VERSION_V6)
		{
			WCHAR result_buf[47]{}; // documented to be large enough for a IPv6 address string
			FAIL_FAST_IF(nullptr == RtlIpv6AddressToStringW(
				reinterpret_cast<const in6_addr*>(&net_event->header.localAddrV6),
				result_buf));
			result += result_buf;
			if (net_event->header.scopeId != 0)
			{
				result += L"%" + std::to_wstring(net_event->header.scopeId);
			}
		}
		else
		{
			result += L"(unknown IPVersion for the local address " + std::to_wstring(net_event->header.ipVersion) + L")";
		}
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)
		{
			result += L" : " + std::to_wstring(net_event->header.localPort);
		}
		result += L"\n";
	}
	else
	{
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)
		{
			result += L"    LocalPort: " + std::to_wstring(net_event->header.localPort) + L"\n";
		}
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
	{
		result += L"    RemoteAddr: ";
		if (net_event->header.ipVersion == FWP_IP_VERSION_V4)
		{
			WCHAR result_buf[17]{}; // documented to be large enough for a IPv4 address string
			FAIL_FAST_IF(nullptr == RtlIpv4AddressToStringW(
				reinterpret_cast<const in_addr*>(&net_event->header.remoteAddrV4),
				result_buf));
			result += result_buf;
		}
		else if (net_event->header.ipVersion == FWP_IP_VERSION_V6)
		{
			WCHAR result_buf[47]{}; // documented to be large enough for a IPv6 address string
			FAIL_FAST_IF(nullptr == RtlIpv6AddressToStringW(
				reinterpret_cast<const in6_addr*>(&net_event->header.remoteAddrV6),
				result_buf));
			result += result_buf;
		}
		else
		{
			result += L"(unknown IPVersion for the remote address " + std::to_wstring(net_event->header.ipVersion) + L")";
		}
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
		{
			result += L" : " + std::to_wstring(net_event->header.remotePort) + L"\n";
		}
		result += L"\n";
	}
	else
	{
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
		{
			result += L"    RemotePort: " + std::to_wstring(net_event->header.remotePort) + L"\n";
		}
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET)
	{
		result += L"    AppId: ";
		if (net_event->header.appId.size > 0 && net_event->header.appId.data)
		{
			result += std::wstring(reinterpret_cast<const WCHAR*>(net_event->header.appId.data), net_event->header.appId.size);
		}
		else
		{
			result += L"Unspecified AppId";
		}
		result += L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_USER_ID_SET)
	{
		result += L"    UserId: ";
		if (net_event->header.userId)
		{
			wil::unique_hlocal_string sid_string;
			if (ConvertSidToStringSid(net_event->header.userId, &sid_string)) {
				result += sid_string.get();
			}
			else
			{
				const auto gle = GetLastError();
				result = L"Failed to convert UserId SID to string. Error: " + std::to_wstring(gle);
			}
		}
		else
		{
			result += L"Unspecified UserId";
		}
		result += L"\n";
	}


	if (net_event->header.packageSid)
	{
		result += L"    PackageSid: ";
		wil::unique_hlocal_string sid_string;
		if (ConvertSidToStringSid(net_event->header.userId, &sid_string)) {
			result += sid_string.get();
		}
		else
		{
			const auto gle = GetLastError();
			result = L"Failed to convert UserId SID to string. Error: " + std::to_wstring(gle);
		}
		result += L"\n";
	}

	if (net_event->header.enterpriseId)
	{
		result += L"    EnterpriseId: " + std::wstring(net_event->header.enterpriseId) + L"\n";
	}

	if (net_event->header.policyFlags != 0)
	{
		result += L"    PolicyFlags: 0x" + std::to_wstring(net_event->header.policyFlags) + L"\n";
	}

	if (net_event->header.effectiveName.size > 0 && net_event->header.effectiveName.data)
	{
		const auto* string_start = reinterpret_cast<const wchar_t*>(net_event->header.effectiveName.data);
		result += L"    EffectiveName: ";
		result += std::wstring(string_start, string_start + (net_event->header.effectiveName.size / sizeof(wchar_t)));
		result += L"\n";
	}

	return result;
}

std::wstring PrintNetEventIkeExtMmFailure(const FWPM_NET_EVENT_IKEEXT_MM_FAILURE2*);
std::wstring PrintNetEventIkeExtQmFailure(const FWPM_NET_EVENT_IKEEXT_QM_FAILURE1*);
std::wstring PrintNetEventIkeExtEmFailure(const FWPM_NET_EVENT_IKEEXT_EM_FAILURE1*);
std::wstring PrintNetEventClassifyDrop(const FWPM_NET_EVENT_CLASSIFY_DROP2*);
std::wstring PrintNetEventIpSecKernelDrop(const FWPM_NET_EVENT_IPSEC_KERNEL_DROP0*);
std::wstring PrintNetEventIpSecDosDrop(const FWPM_NET_EVENT_IPSEC_DOSP_DROP0*);
std::wstring PrintNetEventClassifyAllow(const FWPM_NET_EVENT_CLASSIFY_ALLOW0*);
std::wstring PrintNetEventCapabilityDrop(const FWPM_NET_EVENT_CAPABILITY_DROP0*);
std::wstring PrintNetEventCapabilityAllow(const FWPM_NET_EVENT_CAPABILITY_ALLOW0*);
std::wstring PrintNetEventClassifyDropMac(const FWPM_NET_EVENT_CLASSIFY_DROP_MAC0*);
std::wstring PrintNetEventLpmPacketArrival(const FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0*);
inline
std::wstring
PrintNetEventDetailedStruct(const FWPM_NET_EVENT5* net_event)
{
	std::wstring result;
	switch (net_event->type)
	{
	case FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE:
		// print FWPM_NET_EVENT_IKEEXT_MM_FAILURE2
		return PrintNetEventIkeExtMmFailure(net_event->ikeMmFailure);
	case FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE:
		// print FWPM_NET_EVENT_IKEEXT_QM_FAILURE1
		return PrintNetEventIkeExtQmFailure(net_event->ikeQmFailure);
	case FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE:
		// print FWPM_NET_EVENT_IKEEXT_EM_FAILURE1
		return PrintNetEventIkeExtEmFailure(net_event->ikeEmFailure);
	case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
		// print FWPM_NET_EVENT_CLASSIFY_DROP2
		return PrintNetEventClassifyDrop(net_event->classifyDrop);
	case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
		// print FWPM_NET_EVENT_IPSEC_KERNEL_DROP0
		return PrintNetEventIpSecKernelDrop(net_event->ipsecDrop);
	case FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP:
		// print FWPM_NET_EVENT_IPSEC_DOSP_DROP0
		return PrintNetEventIpSecDosDrop(net_event->idpDrop);
	case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
		// print FWPM_NET_EVENT_CLASSIFY_ALLOW0
		return PrintNetEventClassifyAllow(net_event->classifyAllow);
	case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
		// print FWPM_NET_EVENT_CAPABILITY_DROP0
		return PrintNetEventCapabilityDrop(net_event->capabilityDrop);
	case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
		// print FWPM_NET_EVENT_CAPABILITY_ALLOW0
		return PrintNetEventCapabilityAllow(net_event->capabilityAllow);
	case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
		// print FWPM_NET_EVENT_CLASSIFY_DROP_MAC0
		return PrintNetEventClassifyDropMac(net_event->classifyDropMac);
	case FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL:
		// print FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0
		return PrintNetEventLpmPacketArrival(net_event->lpmPacketArrival);
	default:
		return L"(unknown FWPM_NET_EVENT_TYPE (not expected - should never see this) - " + std::to_wstring(net_event->type) + L")";
	}
}

inline std::wstring PrintNetEventIkeExtMmFailure(const FWPM_NET_EVENT_IKEEXT_MM_FAILURE2* event)
{
	std::wstring result;

	result += L"    FailureErrorCode: " + std::to_wstring(event->failureErrorCode) + L"\n";
	result += L"    FailurePoint: " + std::to_wstring(event->failurePoint) + L"\n";
	result += L"    Flags: 0x" + std::to_wstring(event->flags) + L"\n";
	result += L"    KeyingModuleType: " + std::to_wstring(event->keyingModuleType) + L"\n";
	result += L"    MmState: " + std::to_wstring(event->mmState) + L"\n";
	result += L"    SaRole: " + std::to_wstring(event->saRole) + L"\n";
	result += L"    MmAuthMethod: " + std::to_wstring(event->mmAuthMethod) + L"\n";

	result += L"    EndCertHash: ";
	for (const unsigned char i : event->endCertHash)
	{
		WCHAR buf[4];
		swprintf_s(buf, L"%02x", i);
		result += buf;
	}
	result += L"\n";

	result += L"    MmId: " + std::to_wstring(event->mmId) + L"\n";
	result += L"    MmFilterId: " + std::to_wstring(event->mmFilterId) + L"\n";

	if (event->localPrincipalNameForAuth)
	{
		result += L"    LocalPrincipalNameForAuth: " + std::wstring(event->localPrincipalNameForAuth) + L"\n";
	}

	if (event->remotePrincipalNameForAuth)
	{
		result += L"    RemotePrincipalNameForAuth: " + std::wstring(event->remotePrincipalNameForAuth) + L"\n";
	}

	result += L"    NumLocalPrincipalGroupSids: " + std::to_wstring(event->numLocalPrincipalGroupSids) + L"\n";
	if (event->numLocalPrincipalGroupSids > 0 && event->localPrincipalGroupSids)
	{
		for (UINT32 i = 0; i < event->numLocalPrincipalGroupSids; ++i)
		{
			if (event->localPrincipalGroupSids[i])
			{
				result += L"      LocalPrincipalGroupSid[" + std::to_wstring(i) + L"]: " + std::wstring(event->localPrincipalGroupSids[i]) + L"\n";
			}
		}
	}

	result += L"    NumRemotePrincipalGroupSids: " + std::to_wstring(event->numRemotePrincipalGroupSids) + L"\n";
	if (event->numRemotePrincipalGroupSids > 0 && event->remotePrincipalGroupSids)
	{
		for (UINT32 i = 0; i < event->numRemotePrincipalGroupSids; ++i)
		{
			if (event->remotePrincipalGroupSids[i])
			{
				result += L"      RemotePrincipalGroupSid[" + std::to_wstring(i) + L"]: " + std::wstring(event->remotePrincipalGroupSids[i]) + L"\n";
			}
		}
	}

	if (event->providerContextKey)
	{
		WCHAR guid_str[40];
		StringFromGUID2(*event->providerContextKey, guid_str, 40);
		result += L"    ProviderContextKey: " + std::wstring(guid_str) + L"\n";
	}

	return result;
}

inline std::wstring PrintNetEventIkeExtQmFailure(const FWPM_NET_EVENT_IKEEXT_QM_FAILURE1* event)
{
	std::wstring result;

	result += L"    FailureErrorCode: " + std::to_wstring(event->failureErrorCode) + L"\n";
	result += L"    FailurePoint: " + std::to_wstring(event->failurePoint) + L"\n";
	result += L"    KeyingModuleType: " + std::to_wstring(event->keyingModuleType) + L"\n";
	result += L"    QmState: " + std::to_wstring(event->qmState) + L"\n";
	result += L"    SaRole: " + std::to_wstring(event->saRole) + L"\n";
	result += L"    SaTrafficType: " + std::to_wstring(event->saTrafficType) + L"\n";

	result += L"    QmFilterId: " + std::to_wstring(event->qmFilterId) + L"\n";
	result += L"    MmSaLuid: " + std::to_wstring(event->mmSaLuid) + L"\n";

	WCHAR guid_str[40];
	StringFromGUID2(event->mmProviderContextKey, guid_str, 40);
	result += L"    MmProviderContextKey: " + std::wstring(guid_str) + L"\n";

	return result;
}

inline std::wstring PrintNetEventIkeExtEmFailure(const FWPM_NET_EVENT_IKEEXT_EM_FAILURE1* event)
{
	std::wstring result;

	result += L"    FailureErrorCode: " + std::to_wstring(event->failureErrorCode) + L"\n";
	result += L"    FailurePoint: " + std::to_wstring(event->failurePoint) + L"\n";
	result += L"    Flags: 0x" + std::to_wstring(event->flags) + L"\n";
	result += L"    EmState: " + std::to_wstring(event->emState) + L"\n";
	result += L"    SaRole: " + std::to_wstring(event->saRole) + L"\n";
	result += L"    EmAuthMethod: " + std::to_wstring(event->emAuthMethod) + L"\n";

	result += L"    EndCertHash: ";
	for (unsigned char i : event->endCertHash)
    {
		WCHAR buf[4];
		swprintf_s(buf, L"%02x", i);
		result += buf;
	}
	result += L"\n";

	result += L"    MmId: " + std::to_wstring(event->mmId) + L"\n";
	result += L"    QmFilterId: " + std::to_wstring(event->qmFilterId) + L"\n";

	if (event->localPrincipalNameForAuth)
	{
		result += L"    LocalPrincipalNameForAuth: " + std::wstring(event->localPrincipalNameForAuth) + L"\n";
	}

	if (event->remotePrincipalNameForAuth)
	{
		result += L"    RemotePrincipalNameForAuth: " + std::wstring(event->remotePrincipalNameForAuth) + L"\n";
	}

	result += L"    NumLocalPrincipalGroupSids: " + std::to_wstring(event->numLocalPrincipalGroupSids) + L"\n";
	if (event->numLocalPrincipalGroupSids > 0 && event->localPrincipalGroupSids)
	{
		for (UINT32 i = 0; i < event->numLocalPrincipalGroupSids; ++i)
		{
			if (event->localPrincipalGroupSids[i])
			{
				result += L"      LocalPrincipalGroupSid[" + std::to_wstring(i) + L"]: " + std::wstring(event->localPrincipalGroupSids[i]) + L"\n";
			}
		}
	}

	result += L"    NumRemotePrincipalGroupSids: " + std::to_wstring(event->numRemotePrincipalGroupSids) + L"\n";
	if (event->numRemotePrincipalGroupSids > 0 && event->remotePrincipalGroupSids)
	{
		for (UINT32 i = 0; i < event->numRemotePrincipalGroupSids; ++i)
		{
			if (event->remotePrincipalGroupSids[i])
			{
				result += L"      RemotePrincipalGroupSid[" + std::to_wstring(i) + L"]: " + std::wstring(event->remotePrincipalGroupSids[i]) + L"\n";
			}
		}
	}

	result += L"    SA-TrafficType: " + std::to_wstring(event->saTrafficType) + L"\n";

	return result;
}

inline std::wstring PrintNetEventClassifyDrop(const FWPM_NET_EVENT_CLASSIFY_DROP2* event)
{
	std::wstring result;

	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    LayerId: " + std::to_wstring(event->layerId) + L"\n";
	result += L"    ReauthReason: " + std::to_wstring(event->reauthReason) + L"\n";
	result += L"    OriginalProfile: " + std::to_wstring(event->originalProfile) + L"\n";
	result += L"    CurrentProfile: " + std::to_wstring(event->currentProfile) + L"\n";
	result += L"    MsFwpDirection: " + std::to_wstring(event->msFwpDirection) + L"\n";
	result += L"    IsLoopback: " + std::wstring(event->isLoopback ? L"TRUE" : L"FALSE") + L"\n";

	if (event->vSwitchId.size > 0 && event->vSwitchId.data)
	{
		result += L"    VSwitchId: ";
		for (UINT32 i = 0; i < event->vSwitchId.size; ++i)
		{
			WCHAR buf[4];
			swprintf_s(buf, L"%02x", event->vSwitchId.data[i]);
			result += buf;
		}
		result += L"\n";
	}

	result += L"    VSwitchSourcePort: " + std::to_wstring(event->vSwitchSourcePort) + L"\n";
	result += L"    VSwitchDestinationPort: " + std::to_wstring(event->vSwitchDestinationPort) + L"\n";

	return result;
}

inline std::wstring PrintNetEventIpSecKernelDrop(const FWPM_NET_EVENT_IPSEC_KERNEL_DROP0* event)
{
	std::wstring result;

	result += L"    FailureStatus: " + std::to_wstring(event->failureStatus) + L"\n";
	result += L"    Direction: " + std::to_wstring(event->direction) + L"\n";
	result += L"    Spi: " + std::to_wstring(event->spi) + L"\n";
	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    LayerId: " + std::to_wstring(event->layerId) + L"\n";

	return result;
}

inline std::wstring PrintNetEventIpSecDosDrop(const FWPM_NET_EVENT_IPSEC_DOSP_DROP0* event)
{
	std::wstring result;

	result += L"    IpVersion: ";
	switch (event->ipVersion)
	{
	case FWP_IP_VERSION_V4:
		result += L"IPv4\n";
		result += L"    PublicHostV4Addr: ";
		{
			WCHAR result_buf[17]{};
			if (RtlIpv4AddressToStringW(reinterpret_cast<const in_addr*>(&event->publicHostV4Addr), result_buf))
			{
				result += result_buf;
			}
		}
		result += L"\n";
		result += L"    InternalHostV4Addr: ";
		{
			WCHAR result_buf[17]{};
			if (RtlIpv4AddressToStringW(reinterpret_cast<const in_addr*>(&event->internalHostV4Addr), result_buf))
			{
				result += result_buf;
			}
		}
		result += L"\n";
		break;
	case FWP_IP_VERSION_V6:
		result += L"IPv6\n";
		result += L"    PublicHostV6Addr: ";
		{
			WCHAR result_buf[47]{};
			if (RtlIpv6AddressToStringW(reinterpret_cast<const in6_addr*>(event->publicHostV6Addr), result_buf))
			{
				result += result_buf;
			}
		}
		result += L"\n";
		result += L"    InternalHostV6Addr: ";
		{
			WCHAR result_buf[47]{};
			if (RtlIpv6AddressToStringW(reinterpret_cast<const in6_addr*>(event->internalHostV6Addr), result_buf))
			{
				result += result_buf;
			}
		}
		result += L"\n";
		break;
	default:
		result += L"(unknown)\n";
		break;
	}

	result += L"    FailureStatus: " + std::to_wstring(event->failureStatus) + L"\n";
	result += L"    Direction: " + std::to_wstring(event->direction) + L"\n";

	return result;
}

inline std::wstring PrintNetEventClassifyAllow(const FWPM_NET_EVENT_CLASSIFY_ALLOW0* event)
{
	std::wstring result;

	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    LayerId: " + std::to_wstring(event->layerId) + L"\n";
	result += L"    ReauthReason: " + std::to_wstring(event->reauthReason) + L"\n";
	result += L"    OriginalProfile: " + std::to_wstring(event->originalProfile) + L"\n";
	result += L"    CurrentProfile: " + std::to_wstring(event->currentProfile) + L"\n";
	result += L"    MsFwpDirection: " + std::to_wstring(event->msFwpDirection) + L"\n";
	result += L"    IsLoopback: " + std::wstring(event->isLoopback ? L"TRUE" : L"FALSE") + L"\n";

	return result;
}

inline std::wstring PrintNetEventCapabilityDrop(const FWPM_NET_EVENT_CAPABILITY_DROP0* event)
{
	std::wstring result;

	result += L"    NetworkCapabilityId: ";
	switch (event->networkCapabilityId)
	{
	case FWPM_APPC_NETWORK_CAPABILITY_INTERNET_CLIENT:
		result += L"INTERNET_CLIENT";
		break;
	case FWPM_APPC_NETWORK_CAPABILITY_INTERNET_CLIENT_SERVER:
		result += L"INTERNET_CLIENT_SERVER";
		break;
	case FWPM_APPC_NETWORK_CAPABILITY_INTERNET_PRIVATE_NETWORK:
		result += L"INTERNET_PRIVATE_NETWORK";
		break;
	default:
		result += L"(unknown - " + std::to_wstring(event->networkCapabilityId) + L")";
		break;
	}
	result += L"\n";

	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    IsLoopback: " + std::wstring(event->isLoopback ? L"TRUE" : L"FALSE") + L"\n";

	return result;
}

inline std::wstring PrintNetEventCapabilityAllow(const FWPM_NET_EVENT_CAPABILITY_ALLOW0* event)
{
	std::wstring result;

	result += L"    NetworkCapabilityId: ";
	switch (event->networkCapabilityId)
	{
	case FWPM_APPC_NETWORK_CAPABILITY_INTERNET_CLIENT:
		result += L"INTERNET_CLIENT";
		break;
	case FWPM_APPC_NETWORK_CAPABILITY_INTERNET_CLIENT_SERVER:
		result += L"INTERNET_CLIENT_SERVER";
		break;
	case FWPM_APPC_NETWORK_CAPABILITY_INTERNET_PRIVATE_NETWORK:
		result += L"INTERNET_PRIVATE_NETWORK";
		break;
	default:
		result += L"(unknown - " + std::to_wstring(event->networkCapabilityId) + L")";
		break;
	}
	result += L"\n";

	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    IsLoopback: " + std::wstring(event->isLoopback ? L"TRUE" : L"FALSE") + L"\n";

	return result;
}

inline std::wstring PrintNetEventClassifyDropMac(const FWPM_NET_EVENT_CLASSIFY_DROP_MAC0* event)
{
	std::wstring result;

	result += L"    LocalMacAddr: ";
	for (int i = 0; i < 6; ++i)
	{
		WCHAR buf[4];
		swprintf_s(buf, L"%02x", event->localMacAddr.byteArray6[i]);
		result += buf;
		if (i < 5) result += L":";
	}
	result += L"\n";

	result += L"    RemoteMacAddr: ";
	for (int i = 0; i < 6; ++i)
	{
		WCHAR buf[4];
		swprintf_s(buf, L"%02x", event->remoteMacAddr.byteArray6[i]);
		result += buf;
		if (i < 5) result += L":";
	}
	result += L"\n";

	result += L"    MediaType: " + std::to_wstring(event->mediaType) + L"\n";
	result += L"    IfType: " + std::to_wstring(event->ifType) + L"\n";
	result += L"    EtherType: 0x" + std::to_wstring(event->etherType) + L"\n";
	result += L"    NdisPortNumber: " + std::to_wstring(event->ndisPortNumber) + L"\n";
	result += L"    Reserved: " + std::to_wstring(event->reserved) + L"\n";
	result += L"    VlanTag: " + std::to_wstring(event->vlanTag) + L"\n";
	result += L"    IfLuid: " + std::to_wstring(event->ifLuid) + L"\n";
	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    LayerId: " + std::to_wstring(event->layerId) + L"\n";
	result += L"    ReauthReason: " + std::to_wstring(event->reauthReason) + L"\n";
	result += L"    OriginalProfile: " + std::to_wstring(event->originalProfile) + L"\n";
	result += L"    CurrentProfile: " + std::to_wstring(event->currentProfile) + L"\n";
	result += L"    MsFwpDirection: " + std::to_wstring(event->msFwpDirection) + L"\n";
	result += L"    IsLoopback: " + std::wstring(event->isLoopback ? L"TRUE" : L"FALSE") + L"\n";

	if (event->vSwitchId.size > 0 && event->vSwitchId.data)
	{
		result += L"    VSwitchId: ";
		for (UINT32 i = 0; i < event->vSwitchId.size; ++i)
		{
			WCHAR buf[4];
			swprintf_s(buf, L"%02x", event->vSwitchId.data[i]);
			result += buf;
		}
		result += L"\n";
	}

	result += L"    VSwitchSourcePort: " + std::to_wstring(event->vSwitchSourcePort) + L"\n";
	result += L"    VSwitchDestinationPort: " + std::to_wstring(event->vSwitchDestinationPort) + L"\n";

	return result;
}

inline std::wstring PrintNetEventLpmPacketArrival(const FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0* event)
{
	std::wstring result;

	result += L"    SA-Spi: " + std::to_wstring(event->spi) + L"\n";

	return result;
}
