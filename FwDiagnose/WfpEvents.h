#pragma once
#include <string>
#include <fwpmu.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <mstcpip.h>
#include <Sddl.h>
#include <nldef.h>

#include <wil/resource.h>

inline
std::wstring
IpProtocolToString(UINT8 protocol)
{
	switch (protocol)
	{
	case IPPROTO_HOPOPTS:
		return L"HOPOPT (0)";
	case IPPROTO_ICMP:
		return L"ICMP (1)";
	case IPPROTO_IGMP:
		return L"IGMP (2)";
	case IPPROTO_GGP:
		return L"GGP (3)";
	case IPPROTO_IPV4:
		return L"IPv4 (4)";
	case IPPROTO_ST:
		return L"ST (5)";
	case IPPROTO_TCP:
		return L"TCP (6)";
	case IPPROTO_CBT:
		return L"CBT (7)";
	case IPPROTO_EGP:
		return L"EGP (8)";
	case IPPROTO_IGP:
		return L"IGP (9)";
	case IPPROTO_PUP:
		return L"PUP (12)";
	case IPPROTO_UDP:
		return L"UDP (17)";
	case IPPROTO_IDP:
		return L"IDP (22)";
	case IPPROTO_RDP:
		return L"RDP (27)";
	case IPPROTO_IPV6:
		return L"IPv6 (41)";
	case IPPROTO_ROUTING:
		return L"IPv6-Route (43)";
	case IPPROTO_FRAGMENT:
		return L"IPv6-Frag (44)";
	case IPPROTO_ESP:
		return L"ESP (50)";
	case IPPROTO_AH:
		return L"AH (51)";
	case IPPROTO_ICMPV6:
		return L"ICMPv6 (58)";
	case IPPROTO_NONE:
		return L"IPv6-NoNxt (59)";
	case IPPROTO_DSTOPTS:
		return L"IPv6-Opts (60)";
	case IPPROTO_ND:
		return L"ND (77)";
	case IPPROTO_ICLFXBM:
		return L"ICLFXBM (78)";
	case IPPROTO_PIM:
		return L"PIM (103)";
	case IPPROTO_PGM:
		return L"PGM (113)";
	case IPPROTO_L2TP:
		return L"L2TP (115)";
	case IPPROTO_SCTP:
		return L"SCTP (132)";
	case IPPROTO_RAW:
		return L"RAW (255)";
	default:
		return L"Unknown Protocol (" + std::to_wstring(protocol) + L")";
	}
}

inline
std::wstring
DirectionToString(UINT32 direction)
{
	switch (direction)
	{
	case 0x00003900L: // FWP_DIRECTION_IN:
		return L"In (0x00003900L)";

	case 0x00003901L: // FWP_DIRECTION_OUT:
		return L"Out (0x00003901L)";

	case 0x00003902L: // FWP_DIRECTION_FORWARD:
		return L"Forward (0x00003902L)";
	}

	return L"(unknown FWP_DIRECTION - " + std::to_wstring(direction) + L")";
}

inline
std::wstring
ProfileToString(UINT32 profile)
{
	switch (profile)
	{
	case NL_INTERFACE_NETWORK_CATEGORY_STATE::NlincCategoryUnknown:
		return L"Unknown (0)";
	case NL_INTERFACE_NETWORK_CATEGORY_STATE::NlincPublic:
		return L"Public (1)";
	case NL_INTERFACE_NETWORK_CATEGORY_STATE::NlincPrivate:
		return L"Private (2)";
	case NL_INTERFACE_NETWORK_CATEGORY_STATE::NlincDomainAuthenticated:
		return L"DomainAuthenticated (3)";
	}

	return L"(unknown Profile - " + std::to_wstring(profile) + L")";
}

inline
std::wstring
ReauthReasonToString(UINT32 reauthReason)
{
	if (reauthReason == 0)
	{
		return L"not-reauth";
	}

	std::wstring returnString;
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_POLICY_CHANGE)
	{
		returnString += L"POLICY_CHANGE ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_NEW_ARRIVAL_INTERFACE)
	{
		returnString += L"NEW_ARRIVAL_INTERFACE ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_NEW_NEXTHOP_INTERFACE)
	{
		returnString += L"NEW_NEXTHOP_INTERFACE ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_PROFILE_CROSSING)
	{
		returnString += L"PROFILE_CROSSING ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION)
	{
		returnString += L"CLASSIFY_COMPLETION ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_IPSEC_PROPERTIES_CHANGED)
	{
		returnString += L"IPSEC_PROPERTIES_CHANGED ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_MID_STREAM_INSPECTION)
	{
		returnString += L"MID_STREAM_INSPECTION ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_SOCKET_PROPERTY_CHANGED)
	{
		returnString += L"SOCKET_PROPERTY_CHANGED ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_NEW_INBOUND_MCAST_BCAST_PACKET)
	{
		returnString += L"NEW_INBOUND_MCAST_BCAST_PACKET ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_EDP_POLICY_CHANGED)
	{
		returnString += L"EDP_POLICY_CHANGED ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_PROXY_HANDLE_CHANGED)
	{
		returnString += L"PROXY_HANDLE_CHANGED ";
	}
	if (reauthReason & FWP_CONDITION_REAUTHORIZE_REASON_CHECK_OFFLOAD)
	{
		returnString += L"CHECK_OFFLOAD ";
	}
	return returnString;
}

inline
std::wstring
PrintNetEventType(const FWPM_NET_EVENT5* net_event)
{
	switch (net_event->type)
	{
	case FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE:
		return L"  - Type: IKEEXT_MM_FAILURE\n";
	case FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE:
		return L"  - Type: IKEEXT_QM_FAILURE\n";
	case FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE:
		return L"  - Type: IKEEXT_EM_FAILURE\n";
	case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
		return L"  - Type: CLASSIFY_DROP\n";
	case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
		return L"  - Type: IPSEC_KERNEL_DROP\n";
	case FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP:
		return L"  - Type: IPSEC_DOSP_DROP\n";
	case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
		return L"  - Type: CLASSIFY_ALLOW\n";
	case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
		return L"  - Type: CAPABILITY_DROP\n";
	case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
		return L"  - Type: CAPABILITY_ALLOW\n";
	case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
		return L"  - Type: CLASSIFY_DROP_MAC\n";
	case FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL:
		return L"  - Type: LPM_PACKET_ARRIVAL\n";
	case FWPM_NET_EVENT_TYPE_MAX:
	default:
		return L"  - Type: (unknown FWPM_NET_EVENT_TYPE - " + std::to_wstring(net_event->type) + L")\n";
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
	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET)
	{
		result += L"    Processed as part of a Reauth event\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET)
	{
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
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
	{
		result += L"    IPProtocol: " + IpProtocolToString(net_event->header.ipProtocol) + L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET)
	{
		result += L"    LocalAddr: ";
		if (net_event->header.ipVersion == FWP_IP_VERSION_V4)
		{
			WCHAR result_buf[17]{}; // documented to be large enough for a IPv4 address string
			// the UINT32 is in host-byte order, so must convert it before printing
			const auto fixed_address = ntohl(net_event->header.localAddrV4);
			FAIL_FAST_IF(nullptr == RtlIpv4AddressToStringW(
				reinterpret_cast<const in_addr*>(&fixed_address),
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
			if (net_event->header.ipProtocol == IPPROTO_ICMP || net_event->header.ipProtocol == IPPROTO_ICMPV6)
			{
				// TODO: ICMP/ICMPv6 does not have ports - but the port fields are used to communicate Type and Code
			}
			else
			{
				result += L" : " + std::to_wstring(net_event->header.localPort);
			}
		}

		result += L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
	{
		result += L"    RemoteAddr: ";
		if (net_event->header.ipVersion == FWP_IP_VERSION_V4)
		{
			WCHAR result_buf[17]{}; // documented to be large enough for a IPv4 address string
			// the UINT32 is in host-byte order, so must convert it before printing
			const auto fixed_address = ntohl(net_event->header.remoteAddrV4);
			FAIL_FAST_IF(nullptr == RtlIpv4AddressToStringW(
				reinterpret_cast<const in_addr*>(&fixed_address),
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
			if (net_event->header.ipProtocol == IPPROTO_ICMP || net_event->header.ipProtocol == IPPROTO_ICMPV6)
			{
				// TODO: ICMP/ICMPv6 does not have ports - but the port fields are used to communicate Type and Code
			}
			else
			{
				result += L" : " + std::to_wstring(net_event->header.remotePort);
			}
		}
		result += L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET)
	{
		result += L"    AppId: ";
		if (net_event->header.appId.size > 0 && net_event->header.appId.data)
		{
			std::wstring appid_string(
				reinterpret_cast<const wchar_t*>(net_event->header.appId.data),
				net_event->header.appId.size / sizeof(wchar_t));
			std::erase_if(appid_string, [](const auto ch) { return ch == L'\0'; }); // Remove any embedded nulls

			result += appid_string;
		}
		else
		{
			result += L"(null AppId)";
		}
		result += L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_USER_ID_SET)
	{
		result += L"    UserId: ";
		if (net_event->header.userId)
		{
			wil::unique_hlocal_string sid_string;
			if (!ConvertSidToStringSidW(net_event->header.userId, &sid_string)) {
				const auto gle = GetLastError();
				result += wil::str_printf<std::wstring>(L"Failed to convert UserId SID to string (0x%x)", gle);
			}
			else
			{
				std::wstring localUserOwnerName;
				DWORD localUserOwnerNameSize = 0;
				std::wstring localUserDomainName;
				DWORD cchReferencedDomainName = 0;
				SID_NAME_USE sid_name_use{};
				if (!LookupAccountSidW(nullptr, net_event->header.userId, localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
				{
					if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
					{
						localUserOwnerName.resize(localUserOwnerNameSize);
						localUserDomainName.resize(cchReferencedDomainName);

						if (!LookupAccountSidW(nullptr, net_event->header.userId, localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
						{
							const auto gle = GetLastError();
							result += wil::str_printf<std::wstring>(L"[Failed to LookupAccountSid(%ls) (0x%lx)]", sid_string.get(), gle);
						}
						else
						{
							std::erase_if(localUserOwnerName, [](const auto ch) { return ch == L'\0'; }); // Remove any embedded nulls
							std::erase_if(localUserDomainName, [](const auto ch) { return ch == L'\0'; }); // Remove any embedded nulls

							if (localUserDomainName.empty())
							{
								result += wil::str_printf<std::wstring>(
									L"%ls (%ls)",
									localUserOwnerName.c_str(),
									sid_string.get());
							}
							else
							{
								result += wil::str_printf<std::wstring>(
									L"%ls\\%ls (%ls)",
									localUserDomainName.c_str(),
									localUserOwnerName.c_str(),
									sid_string.get());
							}
						}
					}
					else
					{
						const auto gle = GetLastError();
						std::printf("Failed to LookupAccountSid(%ls) (0x%lx)", sid_string.get(), gle);
					}
				}
				else
				{
					// should never happen
					FAIL_FAST();
				}
			}
		}
		else
		{
			result += L"(null UserId)";
		}
		result += L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET)
	{
		result += L"    PackageSid: ";
		if (net_event->header.packageSid)
		{
			wil::unique_hlocal_string sid_string;
			if (ConvertSidToStringSid(net_event->header.packageSid, &sid_string)) {
				result += sid_string.get();
				if (sid_string.get() == std::wstring(L"S-1-0-0"))
				{
					result += L" (null PackageSid)";
				}
			}
			else
			{
				const auto gle = GetLastError();
				result += L"Failed to convert Package SID to string. Error: " + std::to_wstring(gle);
			}
		}
		else
		{
			result += L"(null PackageSid)";
		}
		result += L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_ENTERPRISE_ID_SET)
	{
		if (net_event->header.enterpriseId)
		{
			result += L"    EnterpriseId: " + std::wstring(net_event->header.enterpriseId) + L"\n";
		}
		else
		{
			result += L"    EnterpriseId: (null EnterpriseId)\n";
		}
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_POLICY_FLAGS_SET)
	{
		result += L"    PolicyFlags: 0x" + std::to_wstring(net_event->header.policyFlags) + L"\n";
	}

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_EFFECTIVE_NAME_SET)
	{
		if (net_event->header.effectiveName.size > 0 && net_event->header.effectiveName.data)
		{
			std::wstring effective_name_string(
				reinterpret_cast<const wchar_t*>(net_event->header.effectiveName.data),
				net_event->header.effectiveName.size / sizeof(wchar_t));
			std::erase_if(effective_name_string, [](const auto ch) { return ch == L'\0'; }); // Remove any embedded nulls

			result += L"    EffectiveName: " + effective_name_string + L"\n";
		}
		else
		{
			result += L"    EffectiveName: (null EffectiveName)\n";
		}
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

	if (event->reauthReason != 0)
	{
		result += L"    ReauthReason: " + ReauthReasonToString(event->reauthReason) + L"\n";
	}

	if (event->originalProfile == event->currentProfile)
	{
		result += L"    Profile: " + ProfileToString(event->currentProfile) + L"\n";

	}
	else
	{
		result += L"    OriginalProfile: " + ProfileToString(event->originalProfile) + L"\n";
		result += L"    CurrentProfile: " + ProfileToString(event->currentProfile) + L"\n";
	}

	if (event->isLoopback)
	{
		// writing out that it's not loopback isn't useful
		result += L"    IsLoopback: True\n";
	}

	result += L"    MsFwpDirection: " + DirectionToString(event->msFwpDirection) + L"\n";

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

	if (event->vSwitchSourcePort > 0)
	{
		result += L"    VSwitchSourcePort: " + std::to_wstring(event->vSwitchSourcePort) + L"\n";
	}
	if (event->vSwitchDestinationPort > 0)
	{
		result += L"    VSwitchDestinationPort: " + std::to_wstring(event->vSwitchDestinationPort) + L"\n";
	}

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
	if (event->reauthReason != 0)
	{
		result += L"    ReauthReason: " + ReauthReasonToString(event->reauthReason) + L"\n";
	}

	if (event->originalProfile == event->currentProfile)
	{
		result += L"    Profile: " + ProfileToString(event->currentProfile) + L"\n";

	}
	else
	{
		result += L"    OriginalProfile: " + ProfileToString(event->originalProfile) + L"\n";
		result += L"    CurrentProfile: " + ProfileToString(event->currentProfile) + L"\n";
	}

	if (event->isLoopback)
	{
		// writing out that it's not loopback isn't useful
		result += L"    IsLoopback: True\n";
	}

	result += L"    MsFwpDirection: " + DirectionToString(event->msFwpDirection) + L"\n";

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
	if (event->isLoopback)
	{
		// writing out that it's not loopback isn't useful
		result += L"    IsLoopback: True\n";
	}

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
	if (event->isLoopback)
	{
		// writing out that it's not loopback isn't useful
		result += L"    IsLoopback: True\n";
	}

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
	if (event->reauthReason != 0)
	{
		result += L"    ReauthReason: " + ReauthReasonToString(event->reauthReason) + L"\n";
	}

	if (event->originalProfile == event->currentProfile)
	{
		result += L"    Profile: " + ProfileToString(event->currentProfile) + L"\n";

	}
	else
	{
		result += L"    OriginalProfile: " + ProfileToString(event->originalProfile) + L"\n";
		result += L"    CurrentProfile: " + ProfileToString(event->currentProfile) + L"\n";
	}

	if (event->isLoopback)
	{
		// writing out that it's not loopback isn't useful
		result += L"    IsLoopback: True\n";
	}

	result += L"    MsFwpDirection: " + DirectionToString(event->msFwpDirection) + L"\n";

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

	if (event->vSwitchSourcePort > 0)
	{
		result += L"    VSwitchSourcePort: " + std::to_wstring(event->vSwitchSourcePort) + L"\n";
	}
	if (event->vSwitchDestinationPort > 0)
	{
		result += L"    VSwitchDestinationPort: " + std::to_wstring(event->vSwitchDestinationPort) + L"\n";
	}

	return result;
}

inline std::wstring PrintNetEventLpmPacketArrival(const FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0* event)
{
	std::wstring result;

	result += L"    SA-Spi: " + std::to_wstring(event->spi) + L"\n";

	return result;
}
