// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <string>

#include <windows.h>
#include <Objbase.h>
#include <Sddl.h>
#include <nldef.h>

#include <fwpmu.h>

#include "FirewallRules.h"
#include "IpProperties.h"
#include "WfpCounters.h"
#include "WfpEvents.h"

#include <ctEtwReader.hpp>
#include <wil/stl.h>
#include <wil/network.h>
#include <wil/resource.h>

static
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

static
std::wstring
IpProtocolToString(int protocol)
{
	if (protocol > 0xff)
	{
		return L"Unknown Protocol (" + std::to_wstring(protocol) + L")";
	}
	return IpProtocolToString(static_cast<UINT8>(protocol));
}

static
std::wstring
DirectionToString(UINT32 direction)
{
	switch (direction)
	{
	case 0x00003900L: // FWP_DIRECTION_IN:
		return L"In";

	case 0x00003901L: // FWP_DIRECTION_OUT:
		return L"Out";

	case 0x00003902L: // FWP_DIRECTION_FORWARD:
		return L"Forward";
	}

	return L"(unknown FWP_DIRECTION - " + std::to_wstring(direction) + L")";
}

static
std::wstring
ProfileToString(UINT32 profile)
{
	switch (profile)
	{
	case NlincCategoryUnknown:
		return L"Unknown";
	case NlincPublic:
		return L"Public";
	case NlincPrivate:
		return L"Private";
	case NlincDomainAuthenticated:
		return L"DomainAuthenticated";
	}

	return L"(unknown Profile - " + std::to_wstring(profile) + L")";
}

static
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

// leveraged information from https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
// and https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
static
std::wstring
PrintIcmpType(UINT8 protocol, UINT16 type)
{
	if (protocol == IPPROTO_ICMP)
	{
		switch (type)
		{
		case 0: return L"Echo Reply (0)";
		case 3: return L"Destination Unreachable (3)";
		case 4: return L"Source Quench [Deprecated] (4)";
		case 5: return L"Redirect (5)";
		case 6: return L"Alternate Host Address [Deprecated] (6)";
		case 8: return L"Echo (8)";
		case 9: return L"Router Advertisement (9)";
		case 10: return L"Router Solicitation (10)";
		case 11: return L"Time Exceeded (11)";
		case 12: return L"Parameter Problem (12)";
		case 13: return L"Timestamp (13)";
		case 14: return L"Timestamp Reply (14)";
		case 15: return L"Information Request [Deprecated] (15)";
		case 16: return L"Information Reply [Deprecated] (16)";
		case 17: return L"Address Mask Request [Deprecated] (17)";
		case 18: return L"Address Mask Reply [Deprecated] (18)";
		case 19: return L"Reserved (for Security) (19)";
		case 20: case 21: case 22: case 23: case 24:
		case 25: case 26: case 27: case 28: case 29:
			return L"Reserved (for Robustness Experiment) (" + std::to_wstring(type) + L")";
		case 30: return L"Traceroute [Deprecated] (30)";
		case 31: return L"Datagram Conversion Error [Deprecated] (31)";
		case 32: return L"Mobile Host Redirect [Deprecated] (32)";
		case 33: return L"IPv6 Where-Are-You [Deprecated] (33)";
		case 34: return L"IPv6 I-Am-Here [Deprecated] (34)";
		case 35: return L"Mobile Registration Request [Deprecated] (35)";
		case 36: return L"Mobile Registration Reply [Deprecated] (36)";
		case 37: return L"Domain Name Request [Deprecated] (37)";
		case 38: return L"Domain Name Reply [Deprecated] (38)";
		case 39: return L"SKIP [Deprecated] (39)";
		case 40: return L"Photuris (40)";
		case 41: return L"ICMP messages utilized by experimental mobility protocols such as Seamoby (41)";
		case 42: return L"Extended Echo Request (42)";
		case 43: return L"Extended Echo Reply (43)";
		case 253: return L"RFC3692-style Experiment 1 (253)";
		case 254: return L"RFC3692-style Experiment 2 (254)";
		case 255: return L"Reserved (255)";
		default:
			if (type == 1 || type == 2 || type == 7 || type >= 44 && type <= 252)
			{
				return L"Unassigned (" + std::to_wstring(type) + L")";
			}
		}
		return L"Unknown ICMP Type (" + std::to_wstring(type) + L")";
	}
	if (protocol == IPPROTO_ICMPV6)
	{
		switch (type)
		{
		case 0: return L"Reserved (0)";
		case 1: return L"Destination Unreachable (1)";
		case 2: return L"Packet Too Big (2)";
		case 3: return L"Time Exceeded (3)";
		case 4: return L"Parameter Problem (4)";
		case 100: return L"Private experimentation (100)";
		case 101: return L"Private experimentation (101)";
		case 127: return L"Reserved for expansion of ICMPv6 error messages (127)";
		case 128: return L"Echo Request (128)";
		case 129: return L"Echo Reply (129)";
		case 130: return L"Multicast Listener Query (130)";
		case 131: return L"Multicast Listener Report (131)";
		case 132: return L"Multicast Listener Done (132)";
		case 133: return L"Router Solicitation (133)";
		case 134: return L"Router Advertisement (134)";
		case 135: return L"Neighbor Solicitation (135)";
		case 136: return L"Neighbor Advertisement (136)";
		case 137: return L"Redirect Message (137)";
		case 138: return L"Router Renumbering (138)";
		case 139: return L"ICMP Node Information Query (139)";
		case 140: return L"ICMP Node Information Response (140)";
		case 141: return L"Inverse Neighbor Discovery Solicitation Message (141)";
		case 142: return L"Inverse Neighbor Discovery Advertisement Message (142)";
		case 143: return L"Version 2 Multicast Listener Report (143)";
		case 144: return L"Home Agent Address Discovery Request Message (144)";
		case 145: return L"Home Agent Address Discovery Reply Message (145)";
		case 146: return L"Mobile Prefix Solicitation (146)";
		case 147: return L"Mobile Prefix Advertisement (147)";
		case 148: return L"Certification Path Solicitation Message (148)";
		case 149: return L"Certification Path Advertisement Message (149)";
		case 150: return L"ICMP messages utilized by experimental mobility protocols such as Seamoby (150)";
		case 151: return L"Multicast Router Advertisement (151)";
		case 152: return L"Multicast Router Solicitation (152)";
		case 153: return L"Multicast Router Termination (153)";
		case 154: return L"FMIPv6 Messages (154)";
		case 155: return L"RPL Control Message (155)";
		case 156: return L"ILNPv6 Locator Update Message (156)";
		case 157: return L"Duplicate Address Request (157)";
		case 158: return L"Duplicate Address Confirmation (158)";
		case 159: return L"MPL Control Message (159)";
		case 160: return L"Extended Echo Request (160)";
		case 161: return L"Extended Echo Reply (161)";
		case 200: return L"Private experimentation (200)";
		case 201: return L"Private experimentation (201)";
		case 255: return L"Reserved for expansion of ICMPv6 informational messages (255)";
		default:
			if ((type >= 5 && type <= 99) || (type >= 102 && type <= 126) || (type >= 162 && type <= 199) || (type >= 202 && type <= 254))
			{
				return L"Unassigned (" + std::to_wstring(type) + L")";
			}
		}
	}
	return L"Unknown ICMPv6 Type (" + std::to_wstring(type) + L")";
}

static
std::wstring
PrintIcmpCode(UINT8 protocol, UINT16 type, UINT16 code)
{
	if (protocol == IPPROTO_ICMP)
	{
		switch (type)
		{
		case 3: // Destination Unreachable
		{
			switch (code)
			{
			case 0: return L"Net Unreachable (0)";
			case 1: return L"Host Unreachable (1)";
			case 2: return L"Protocol Unreachable (2)";
			case 3: return L"Port Unreachable (3)";
			case 4: return L"Fragmentation Needed and Don't Fragment was Set (4)";
			case 5: return L"Source Route Failed (5)";
			case 6: return L"Destination Network Unknown (6)";
			case 7: return L"Destination Host Unknown (7)";
			case 8: return L"Source Host Isolated (8)";
			case 9: return L"Communication with Destination Network is Administratively Prohibited (9)";
			case 10: return L"Communication with Destination Host is Administratively Prohibited (10)";
			case 11: return L"Destination Network Unreachable for Type of Service (11)";
			case 12: return L"Destination Host Unreachable for Type of Service (12)";
			case 13: return L"Communication Administratively Prohibited (13)";
			case 14: return L"Host Precedence Violation (14)";
			case 15: return L"Precedence cutoff in effect (15)";
			}
			break;
		}
		case 5: // Redirect
		{
			switch (code)
			{
			case 0: return L"Redirect Datagram for the Network (0)";
			case 1: return L"Redirect Datagram for the Host (1)";
			case 2: return L"Redirect Datagram for the Type of Service and Network (2)";
			case 3: return L"Redirect Datagram for the Type of Service and Host (3)";
			}
			break;
		}
		case 9: // Router Advertisement
		{
			switch (code)
			{
			case 0: return L"Normal router advertisement (0)";
			case 16: return L"Does not route common traffic (16)";
			}
			break;
		}
		case 11: // Time Exceeded
		{
			switch (code)
			{
			case 0: return L"Time to Live exceeded in Transit (0)";
			case 1: return L"Fragment Reassembly Time Exceeded (1)";
			}
			break;
		}
		case 12: // Parameter Problem
		{
			switch (code)
			{
			case 0: return L"Pointer indicates the error (0)";
			case 1: return L"Missing a Required Option (1)";
			case 2: return L"Bad Length (2)";
			}
			break;
		}
		case 40: // Photuris
		{
			switch (code)
			{
			case 0: return L"Bad SPI (0)";
			case 1: return L"Authentication Failed (1)";
			case 2: return L"Decompression Failed (2)";
			case 3: return L"Decryption Failed (3)";
			case 4: return L"Need Authentication (4)";
			case 5: return L"Need Authorization (5)";
			}
			break;
		}
		case 43: // Extended Echo Reply
		{
			switch (code)
			{
			case 0: return L"No Error (0)";
			case 1: return L"Malformed Query (1)";
			case 2: return L"No Such Interface (2)";
			case 3: return L"No Such Table Entry (3)";
			case 4: return L"Multiple Interfaces Satisfy Query (4)";
			}
			if (code >= 5 && code <= 255)
			{
				return L"Unassigned (" + std::to_wstring(code) + L")";
			}
			break;
		}
		} // switch (type)
		return L"Unknown Code (" + std::to_wstring(code) + L")";
	}
	if (protocol == IPPROTO_ICMPV6)
	{
		switch (type)
		{
		case 1: // Destination Unreachable
		{
			switch (code)
			{
			case 0: return L"No route to destination (0)";
			case 1: return L"Communication with destination administratively prohibited (1)";
			case 2: return L"Beyond scope of source address (2)";
			case 3: return L"Address unreachable (3)";
			case 4: return L"Port unreachable (4)";
			case 5: return L"Source address failed ingress/egress policy (5)";
			case 6: return L"Reject route to destination (6)";
			case 7: return L"Error in Source Routing Header (7)";
			case 8: return L"Headers too long (8)";
			case 9: return L"Error in P-Route (9)";
			}
			break;
		}
		case 3: // Time Exceeded
		{
			switch (code)
			{
			case 0: return L"Hop limit exceeded in transit (0)";
			case 1: return L"Fragment reassembly time exceeded (1)";
			}
			break;
		}
		case 4: // Parameter Problem
		{
			switch (code)
			{
			case 0: return L"Erroneous header field encountered (0)";
			case 1: return L"Unrecognized Next Header type encountered (1)";
			case 2: return L"Unrecognized IPv6 option encountered (2)";
			case 3: return L"IPv6 First Fragment has incomplete IPv6 Header Chain (3)";
			case 4: return L"SR Upper-layer Header Error (4)";
			case 5: return L"Unrecognized Next Header type encountered by intermediate node (5)";
			case 6: return L"Extension header too big (6)";
			case 7: return L"Extension header chain too long (7)";
			case 8: return L"Too many extension headers (8)";
			case 9: return L"Too many options in extension header (9)";
			case 10: return L"Option too big (10)";
			}
			break;
		}
		case 138: // Router Renumbering
		{
			switch (code)
			{
			case 0: return L"Router Renumbering Command (0)";
			case 1: return L"Router Renumbering Result (1)";
			case 255: return L"Sequence Number Reset (255)";
			}
			break;
		}
		case 139: // ICMP Node Information Query
		{
			switch (code)
			{
			case 0: return L"Data field contains an IPv6 address (0)";
			case 1: return L"Data field contains a name (1)";
			case 2: return L"Data field contains an IPv4 address (2)";
			}
			break;
		}
		case 140: // ICMP Node Information Response
		{
			switch (code)
			{
			case 0: return L"A successful reply (0)";
			case 1: return L"The Responder refuses to supply the answer (1)";
			case 2: return L"The Qtype of the Query is unknown to the Responder (2)";
			}
			break;
		}
		case 157: // Duplicate Address Request
		{
			switch (code)
			{
			case 0: return L"DAR message (0)";
			case 1: return L"EDAR message with 64-bit ROVR field (1)";
			case 2: return L"EDAR message with 128-bit ROVR field (2)";
			case 3: return L"EDAR message with 192-bit ROVR field (3)";
			case 4: return L"EDAR message with 256-bit ROVR field (4)";
			}
			if (code >= 5 && code <= 15)
			{
				return L"Unassigned (" + std::to_wstring(code) + L")";
			}
			break;
		}
		case 158: // Duplicate Address Confirmation
		{
			switch (code)
			{
			case 0: return L"DAC message (0)";
			case 1: return L"EDAC message with 64-bit ROVR field (1)";
			case 2: return L"EDAC message with 128-bit ROVR field (2)";
			case 3: return L"EDAC message with 192-bit ROVR field (3)";
			case 4: return L"EDAC message with 256-bit ROVR field (4)";
			}
			if (code >= 5 && code <= 15)
			{
				return L"Unassigned (" + std::to_wstring(code) + L")";
			}
			break;
		}
		case 160:
		{
			switch (code)
			{
			case 0: return L"No Error (0)";
			}
			if (code >= 1 && code <= 255)
			{
				return L"Unassigned (" + std::to_wstring(code) + L")";
			}
			break;
		}
		case 161:
		{
			switch (code)
			{
			case 0: return L"No Error (0)";
			case 1: return L"Malformed Query (1)";
			case 2: return L"No Such Interface (2)";
			case 3: return L"No Such Table Entry (3)";
			case 4: return L"Multiple Interfaces Satisfy Query (4)";
			}
			if (code >= 5 && code <= 255)
			{
				return L"Unassigned (" + std::to_wstring(code) + L")";
			}
			break;
		}
		} // switch (type)
		return L"Unknown Code (" + std::to_wstring(code) + L")";
	}

	FAIL_FAST();
}

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
	/*
	result += L"    Flags: 0x" + std::to_wstring(net_event->header.flags) + L"\n";
	UINT32 flags = net_event->header.flags;
	if (flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
	{
		result += L"           IP-Protocol-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET)
	{
		result += L"           Local-Address-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
	{
		result += L"           Remote-Address-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)
	{
		result += L"           Local-Port-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
	{
		result += L"           Remote-Port-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_APP_ID_SET)
	{
		result += L"           App-ID-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_APP_ID_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_USER_ID_SET)
	{
		result += L"           User-ID-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_USER_ID_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_SCOPE_ID_SET)
	{
		result += L"           Scope-ID-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_SCOPE_ID_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET)
	{
		result += L"           IP-Version-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_IP_VERSION_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET)
	{
		result += L"           Reauth-Reason-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET; <<<<<<<<<<<<<<<<<<<<<<<<<<
	}
	if (flags & FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET)
	{
		result += L"           Package-ID-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_ENTERPRISE_ID_SET)
	{
		result += L"           Enterprise-ID-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_ENTERPRISE_ID_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_POLICY_FLAGS_SET)
	{
		result += L"           Policy-Flags-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_POLICY_FLAGS_SET;
	}
	if (flags & FWPM_NET_EVENT_FLAG_EFFECTIVE_NAME_SET)
	{
		result += L"           Effective-Name-set\n";
		flags &= ~FWPM_NET_EVENT_FLAG_EFFECTIVE_NAME_SET;
	}

	if (flags != 0)
	{
		result += L"           (unknown flags remaining: 0x" + std::to_wstring(flags) + L")\n";
	}
	*/

	if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET)
	{
		result += L"    Reauthorization Event\n";
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
		in_addr local_inaddr{};
		in6_addr local_in6addr{};

		if (net_event->header.ipVersion == FWP_IP_VERSION_V4)
		{
			// the UINT32 is in host-byte order, so must convert it before printing
			local_inaddr.s_addr = ntohl(net_event->header.localAddrV4);

			WCHAR result_buf[17]{}; // documented to be large enough for a IPv4 address string
			FAIL_FAST_IF(nullptr == RtlIpv4AddressToStringW(&local_inaddr, result_buf));
			result += result_buf;
		}
		else if (net_event->header.ipVersion == FWP_IP_VERSION_V6)
		{
			static_assert(sizeof(local_in6addr.u.Byte) == sizeof(net_event->header.localAddrV6), "localAddrV6 size does not match in6_addr size");
			memcpy(&local_in6addr.u.Byte, &net_event->header.localAddrV6, sizeof(local_in6addr));

			WCHAR result_buf[47]{}; // documented to be large enough for a IPv6 address string
			FAIL_FAST_IF(nullptr == RtlIpv6AddressToStringW(&local_in6addr, result_buf));
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
				// ICMP/ICMPv6 does not have ports - but the port fields are used to communicate Type and Code
				// LocalPort == ICMP Type
				// RemotePort == ICMP Code
			}
			else
			{
				result += L" : " + std::to_wstring(net_event->header.localPort);
			}
		}
		result += L"\n";

		// print the interface information for this address
		// 15 == number of spaces so it lines up with the address above - "LocalAddr: "
		if (net_event->header.ipVersion == FWP_IP_VERSION_V4)
		{
			result += PrintIPInterfaceInfo(15, local_inaddr);
		}
		else if (net_event->header.ipVersion == FWP_IP_VERSION_V6)
		{
			result += PrintIPInterfaceInfo(15, local_in6addr);
		}
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
				// ICMP/ICMPv6 does not have ports - but the port fields are used to communicate Type and Code
				// LocalPort == ICMP Type
				// RemotePort == ICMP Code
			}
			else
			{
				result += L" : " + std::to_wstring(net_event->header.remotePort);
			}
		}
		result += L"\n";
	}

	if (net_event->header.ipProtocol == IPPROTO_ICMP || net_event->header.ipProtocol == IPPROTO_ICMPV6)
	{
		// ICMP/ICMPv6 does not have ports - but the port fields are used to communicate Type and Code
		// LocalPort == ICMP Type
		// RemotePort == ICMP Code
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)
		{
			result += L"    ICMP Type: " + PrintIcmpType(net_event->header.ipProtocol, net_event->header.localPort);
			result += L"\n";
		}
		else
		{
			if (net_event->header.localPort != 0)
			{
				result += L"    ICMP Type (event flag not set): " + PrintIcmpType(net_event->header.ipProtocol, net_event->header.localPort);
				result += L"\n";
			}
		}
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
		{
			result += L"    ICMP Code: " + PrintIcmpCode(net_event->header.ipProtocol, net_event->header.localPort, net_event->header.remotePort);
			result += L"\n";
		}
		else
		{
			if (net_event->header.localPort != 0)
			{
				result += L"    ICMP Type (event flag not set): " + PrintIcmpType(net_event->header.ipProtocol, net_event->header.localPort);
				result += L"\n";
			}
		}
		if (net_event->header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
		{
			result += L"    ICMP Code: " + PrintIcmpCode(net_event->header.ipProtocol, net_event->header.localPort, net_event->header.remotePort);
			result += L"\n";
		}
		else
		{
			if (net_event->header.remotePort != 0)
			{
				result += L"    ICMP Code (event flag not set): " + PrintIcmpCode(net_event->header.ipProtocol, net_event->header.localPort, net_event->header.remotePort);
				result += L"\n";
			}
		}
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

std::wstring PrintNetEventIkeExtMmFailure(const FWPM_NET_EVENT_IKEEXT_MM_FAILURE2* event)
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

std::wstring PrintNetEventIkeExtQmFailure(const FWPM_NET_EVENT_IKEEXT_QM_FAILURE1* event)
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

std::wstring PrintNetEventIkeExtEmFailure(const FWPM_NET_EVENT_IKEEXT_EM_FAILURE1* event)
{
	std::wstring result;

	result += L"    FailureErrorCode: " + std::to_wstring(event->failureErrorCode) + L"\n";
	result += L"    FailurePoint: " + std::to_wstring(event->failurePoint) + L"\n";
	result += L"    Flags: 0x" + std::to_wstring(event->flags) + L"\n";
	result += L"    EmState: " + std::to_wstring(event->emState) + L"\n";
	result += L"    SaRole: " + std::to_wstring(event->saRole) + L"\n";
	result += L"    EmAuthMethod: " + std::to_wstring(event->emAuthMethod) + L"\n";

	result += L"    EndCertHash: ";
	for (const unsigned char i : event->endCertHash)
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

std::wstring PrintNetEventClassifyDrop(const FWPM_NET_EVENT_CLASSIFY_DROP2* event)
{
	std::wstring result;

	result += L"    Direction: " + DirectionToString(event->msFwpDirection) + L"\n";
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

std::wstring PrintNetEventIpSecKernelDrop(const FWPM_NET_EVENT_IPSEC_KERNEL_DROP0* event)
{
	std::wstring result;

	result += L"    FailureStatus: " + std::to_wstring(event->failureStatus) + L"\n";
	result += L"    Direction: " + std::to_wstring(event->direction) + L"\n";
	result += L"    Spi: " + std::to_wstring(event->spi) + L"\n";
	result += L"    FilterId: " + std::to_wstring(event->filterId) + L"\n";
	result += L"    LayerId: " + std::to_wstring(event->layerId) + L"\n";

	return result;
}

std::wstring PrintNetEventIpSecDosDrop(const FWPM_NET_EVENT_IPSEC_DOSP_DROP0* event)
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

std::wstring PrintNetEventClassifyAllow(const FWPM_NET_EVENT_CLASSIFY_ALLOW0* event)
{
	std::wstring result;

	result += L"    Direction: " + DirectionToString(event->msFwpDirection) + L"\n";
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

	return result;
}

std::wstring PrintNetEventCapabilityDrop(const FWPM_NET_EVENT_CAPABILITY_DROP0* event)
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

std::wstring PrintNetEventCapabilityAllow(const FWPM_NET_EVENT_CAPABILITY_ALLOW0* event)
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

std::wstring PrintNetEventClassifyDropMac(const FWPM_NET_EVENT_CLASSIFY_DROP_MAC0* event)
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

	result += L"    Direction: " + DirectionToString(event->msFwpDirection) + L"\n";
	result += L"    MediaType: " + std::to_wstring(event->mediaType) + L"\n";
	result += L"    IfType: " + std::to_wstring(event->ifType);
	result += wil::str_printf<std::wstring>(L" (%hs)\n", IfTypeToString(event->ifType).c_str());
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

std::wstring PrintNetEventLpmPacketArrival(const FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0* event)
{
	std::wstring result;

	result += L"    SA-Spi: " + std::to_wstring(event->spi) + L"\n";

	return result;
}

// also listen for TCPIP ETW events for packet drops and failed connections
enum IpDiscardReason
{
	//
	// Receive path discard reasons.
	//
	IpDiscardBadSourceAddress = 1,
	IpDiscardNotLocallyDestined,
	IpDiscardProtocolUnreachable,
	IpDiscardPortUnreachable,
	IpDiscardBadLength,
	IpDiscardMalformedHeader,
	IpDiscardNoRoute,
	IpDiscardBeyondScope,
	IpDiscardInspectionDrop,  // Blocked by firewall, ICMP should not be sent.
	IpDiscardTooManyDecapsulations,
	IpDiscardAdministrativelyProhibited, // Blocked, ICMP should be sent.
	IpDiscardBadChecksum,
	IpDiscardFirstFragmentIncomplete,
	IpDiscardHeaderNotContiguous,
	IpDiscardHeaderNotAligned,

	IpDiscardReceivePathMax = 127,

	//
	// Forward path discard reasons.
	//
	IpDiscardHopLimitExceeded,
	IpDiscardAddressUnreachable,
	IpDiscardRscPacket,
	IpDiscardSourceViolation,
	IpDiscardForwardPathMax = 255,

	//
	// Internally used discard reasons.
	//
	IpDiscardArbitrationUnhandled,
	IpDiscardInspectionAbsorb, // WFP took ownership of the packet.

	//
	// Send path discard reasons not covered above.
	//
	IpDiscardDontFragmentMtuExceeded,
	IpDiscardBufferLengthExceeded,
	IpDiscardAddressResolutionTimeout,
	IpDiscardAddressResolutionFailure,
	IpDiscardIpsecFailure,
	IpDiscardExtensionHeadersFailure,
	IpDiscardAllocationFailure,

	//
	// Discard reasons common to all paths.
	//
	IpDiscardIpsnpiClientDrop,

	IpDiscardUnsupportedOffload,
	IpDiscardRoutingFailure,
	IpDiscardAncillaryDataFailure,
	IpDiscardRawDataFailure,
	IpDiscardSessionStateFailure,

	IpDiscardIpsnpiAllocationFailure,
	IpDiscardIpsnpiModifiedButNotForwarded,
	IpDiscardIpsnpiNoNextHop,
	IpDiscardIpsnpiNoCompartment,
	IpDiscardIpsnpiNoInterface,
	IpDiscardIpsnpiNoSubInterface,
	IpDiscardIpsnpiInterfaceDisabled,
	IpDiscardIpsnpiSegmentationFailed,
	IpDiscardIpsnpiNoEthernetHeader,
	IpDiscardIpsnpiUnexpectedFragment,
	IpDiscardIpsnpiUnsupportedInterfaceType,
	IpDiscardIpsnpiInvalidLsoInfo,
	IpDiscardIpsnpiInvalidUsoInfo,

	IpDiscardInternalError,
	IpDiscardAdministrativelyConfigured,
	IpDiscardBadOption,
	IpDiscardLoopbackDisallowed,
	IpDiscardSmallerScope,
	IpDiscardQueueFull,
	IpDiscardInterfaceDisabled,
	IpDiscardNlClientDiscard,

	IpDiscardIpsnpiUroSegmentSizeExceedsMtu,
	IpDiscardSwUsoFailure,

	IpDiscardMax
};

enum InetDiscardReason {
	InetDiscardSourceUnspecified = 0,
	InetDiscardDestinationMulticast = 1,
	InetDiscardHeaderInvalid = 2,
	InetDiscardChecksumInvalid = 3,
	InetDiscardEndpointNotFound = 4,
	InetDiscardConnectedPath = 5,
	InetDiscardSessionState = 6,
	InetDiscardReceiveInspection = 7,
	InetDiscardAckInvalid = 8,
	InetDiscardExpectedSyn = 9,
	InetDiscardRst = 10,
	InetDiscardSynRcvdSyn = 11,
	InetDiscardSimultaneousConnect = 12,
	InetDiscardPawsFailed = 13,
	InetDiscardLandAttack = 14,
	InetDiscardMissedReset = 15,
	InetDiscardOutsideWindow = 16,
	InetDiscardDuplicateSegment = 17,
	InetDiscardClosedWindow = 18,
	InetDiscardTcbRemoved = 19,
	InetDiscardFinWait2 = 20,
	InetDiscardReassemblyConflict = 21,
	InetDiscardFinReceived = 22,
	InetDiscardListenerInvalidFlags = 23,
	InetDiscardUrgentDeliveryAllocationFailure = 24,
	InetDiscardTcbNotInTcbTable = 25,
	InetDiscardTimeWaitTcbReceivedRstOutsideWindow = 26,
	InetDiscardTimeWaitTcbSynAndOtherFlags = 27,
	InetDiscardTimeWaitTcb = 28,
	InetDiscardSynAckWithFastopenCookieRequest = 29,
	InetDiscardPauseAccept = 30,
	InetDiscardSynAttack = 31,
	InetDiscardAcceptInspection = 32,
	InetDiscardAcceptRedirection = 33,
	InetDiscardReasonMaxEnumValue
};

PCSTR TransportDiscardReasonToString(InetDiscardReason reason) noexcept
{
	switch (reason)
	{
	case InetDiscardSourceUnspecified: return "InetDiscardSourceUnspecified";
	case InetDiscardDestinationMulticast: return "InetDiscardDestinationMulticast";
	case InetDiscardHeaderInvalid: return "InetDiscardHeaderInvalid";
	case InetDiscardChecksumInvalid: return "InetDiscardChecksumInvalid";
	case InetDiscardEndpointNotFound: return "InetDiscardEndpointNotFound";
	case InetDiscardConnectedPath: return "InetDiscardConnectedPath";
	case InetDiscardSessionState: return "InetDiscardSessionState";
	case InetDiscardReceiveInspection: return "InetDiscardReceiveInspection";
	case InetDiscardAckInvalid: return "InetDiscardAckInvalid";
	case InetDiscardExpectedSyn: return "InetDiscardExpectedSyn";
	case InetDiscardRst: return "InetDiscardRst";
	case InetDiscardSynRcvdSyn: return "InetDiscardSynRcvdSyn";
	case InetDiscardSimultaneousConnect: return "InetDiscardSimultaneousConnect";
	case InetDiscardPawsFailed: return "InetDiscardPawsFailed";
	case InetDiscardLandAttack: return "InetDiscardLandAttack";
	case InetDiscardMissedReset: return "InetDiscardMissedReset";
	case InetDiscardOutsideWindow: return "InetDiscardOutsideWindow";
	case InetDiscardDuplicateSegment: return "InetDiscardDuplicateSegment";
	case InetDiscardClosedWindow: return "InetDiscardClosedWindow";
	case InetDiscardTcbRemoved: return "InetDiscardTcbRemoved";
	case InetDiscardFinWait2: return "InetDiscardFinWait2";
	case InetDiscardReassemblyConflict: return "InetDiscardReassemblyConflict";
	case InetDiscardFinReceived: return "InetDiscardFinReceived";
	case InetDiscardListenerInvalidFlags: return "InetDiscardListenerInvalidFlags";
	case InetDiscardUrgentDeliveryAllocationFailure: return "InetDiscardUrgentDeliveryAllocationFailure";
	case InetDiscardTcbNotInTcbTable: return "InetDiscardTcbNotInTcbTable";
	case InetDiscardTimeWaitTcbReceivedRstOutsideWindow: return "InetDiscardTimeWaitTcbReceivedRstOutsideWindow";
	case InetDiscardTimeWaitTcbSynAndOtherFlags: return "InetDiscardTimeWaitTcbSynAndOtherFlags";
	case InetDiscardTimeWaitTcb: return "InetDiscardTimeWaitTcb";
	case InetDiscardSynAckWithFastopenCookieRequest: return "InetDiscardSynAckWithFastopenCookieRequest";
	case InetDiscardPauseAccept: return "InetDiscardPauseAccept";
	case InetDiscardSynAttack: return "InetDiscardSynAttack";
	case InetDiscardAcceptInspection: return "InetDiscardAcceptInspection";
	case InetDiscardAcceptRedirection: return "InetDiscardAcceptRedirection";
	case InetDiscardReasonMaxEnumValue: return "InetDiscardReasonMaxEnumValue";
	default: return "Unknown InetDiscardReason";
	}
}
PCSTR NetworkDiscardReasonToString(IpDiscardReason reason) noexcept
{
	switch (reason)
	{
	case IpDiscardBadSourceAddress: return "IpDiscardBadSourceAddress";
	case IpDiscardNotLocallyDestined: return "IpDiscardNotLocallyDestined";
	case IpDiscardProtocolUnreachable: return "IpDiscardProtocolUnreachable";
	case IpDiscardPortUnreachable: return "IpDiscardPortUnreachable";
	case IpDiscardBadLength: return "IpDiscardBadLength";
	case IpDiscardMalformedHeader: return "IpDiscardMalformedHeader";
	case IpDiscardNoRoute: return "IpDiscardNoRoute";
	case IpDiscardBeyondScope: return "IpDiscardBeyondScope";
	case IpDiscardInspectionDrop: return "IpDiscardInspectionDrop";
	case IpDiscardTooManyDecapsulations: return "IpDiscardTooManyDecapsulations";
	case IpDiscardAdministrativelyProhibited: return "IpDiscardAdministrativelyProhibited";
	case IpDiscardBadChecksum: return "IpDiscardBadChecksum";
	case IpDiscardFirstFragmentIncomplete: return "IpDiscardFirstFragmentIncomplete";
	case IpDiscardHeaderNotContiguous: return "IpDiscardHeaderNotContiguous";
	case IpDiscardHeaderNotAligned: return "IpDiscardHeaderNotAligned";
	case IpDiscardReceivePathMax: return "IpDiscardReceivePathMax";
	case IpDiscardHopLimitExceeded: return "IpDiscardHopLimitExceeded";
	case IpDiscardAddressUnreachable: return "IpDiscardAddressUnreachable";
	case IpDiscardRscPacket: return "IpDiscardRscPacket";
	case IpDiscardSourceViolation: return "IpDiscardSourceViolation";
	case IpDiscardForwardPathMax: return "IpDiscardForwardPathMax";
	case IpDiscardArbitrationUnhandled: return "IpDiscardArbitrationUnhandled";
	case IpDiscardInspectionAbsorb: return "IpDiscardInspectionAbsorb";
	case IpDiscardDontFragmentMtuExceeded: return "IpDiscardDontFragmentMtuExceeded";
	case IpDiscardBufferLengthExceeded: return "IpDiscardBufferLengthExceeded";
	case IpDiscardAddressResolutionTimeout: return "IpDiscardAddressResolutionTimeout";
	case IpDiscardAddressResolutionFailure: return "IpDiscardAddressResolutionFailure";
	case IpDiscardIpsecFailure: return "IpDiscardIpsecFailure";
	case IpDiscardExtensionHeadersFailure: return "IpDiscardExtensionHeadersFailure";
	case IpDiscardAllocationFailure: return "IpDiscardAllocationFailure";
	case IpDiscardIpsnpiClientDrop: return "IpDiscardIpsnpiClientDrop";
	case IpDiscardUnsupportedOffload: return "IpDiscardUnsupportedOffload";
	case IpDiscardRoutingFailure: return "IpDiscardRoutingFailure";
	case IpDiscardAncillaryDataFailure: return "IpDiscardAncillaryDataFailure";
	case IpDiscardRawDataFailure: return "IpDiscardRawDataFailure";
	case IpDiscardSessionStateFailure: return "IpDiscardSessionStateFailure";
	case IpDiscardIpsnpiAllocationFailure: return "IpDiscardIpsnpiAllocationFailure";
	case IpDiscardIpsnpiModifiedButNotForwarded: return "IpDiscardIpsnpiModifiedButNotForwarded";
	case IpDiscardIpsnpiNoNextHop: return "IpDiscardIpsnpiNoNextHop";
	case IpDiscardIpsnpiNoCompartment: return "IpDiscardIpsnpiNoCompartment";
	case IpDiscardIpsnpiNoInterface: return "IpDiscardIpsnpiNoInterface";
	case IpDiscardIpsnpiNoSubInterface: return "IpDiscardIpsnpiNoSubInterface";
	case IpDiscardIpsnpiInterfaceDisabled: return "IpDiscardIpsnpiInterfaceDisabled";
	case IpDiscardIpsnpiSegmentationFailed: return "IpDiscardIpsnpiSegmentationFailed";
	case IpDiscardIpsnpiNoEthernetHeader: return "IpDiscardIpsnpiNoEthernetHeader";
	case IpDiscardIpsnpiUnexpectedFragment: return "IpDiscardIpsnpiUnexpectedFragment";
	case IpDiscardIpsnpiUnsupportedInterfaceType: return "IpDiscardIpsnpiUnsupportedInterfaceType";
	case IpDiscardIpsnpiInvalidLsoInfo: return "IpDiscardIpsnpiInvalidLsoInfo";
	case IpDiscardIpsnpiInvalidUsoInfo: return "IpDiscardIpsnpiInvalidUsoInfo";
	case IpDiscardInternalError: return "IpDiscardInternalError";
	case IpDiscardAdministrativelyConfigured: return "IpDiscardAdministrativelyConfigured";
	case IpDiscardBadOption: return "IpDiscardBadOption";
	case IpDiscardLoopbackDisallowed: return "IpDiscardLoopbackDisallowed";
	case IpDiscardSmallerScope: return "IpDiscardSmallerScope";
	case IpDiscardQueueFull: return "IpDiscardQueueFull";
	case IpDiscardInterfaceDisabled: return "IpDiscardInterfaceDisabled";
	case IpDiscardNlClientDiscard: return "IpDiscardNlClientDiscard";
	case IpDiscardIpsnpiUroSegmentSizeExceedsMtu: return "IpDiscardIpsnpiUroSegmentSizeExceedsMtu";
	case IpDiscardSwUsoFailure: return "IpDiscardSwUsoFailure";
	case IpDiscardMax: return "IpDiscardMax";
	default: return "<unknown IpDiscardReason>";
	}
}
void ListenForWfpNetEvents()
{
	// verify has admin access
	if (!HasFirewallAdminAccess())
	{
		std::printf("  Administrative privileges required - try running from an elevated Administrator command prompt.\n");
		THROW_WIN32(ERROR_ACCESS_DENIED);
	}

	// sort filters by filter id for fast lookup
	SortFilterDetailsByFilterId();

	FWPM_NET_EVENT_SUBSCRIPTION0 subscription_info{};
	THROW_IF_FAILED(CoCreateGuid(&subscription_info.sessionKey));

	constexpr auto TcpipTransportPacketDrops = 1214;
	constexpr auto TcpipNetworkPacketDropEventId = 1215;
	constexpr auto TcpipFramingPacketDrops = 1465;
	const auto callback_fn = [](const EVENT_RECORD* pRecord) {
		try
		{
			// Process the ETW event record
			const auto event_message = ctl::ctEtwRecord(pRecord);

			if (event_message.getEventId() == TcpipTransportPacketDrops)
			{
				const auto protocol_string = event_message.readEventProperty(L"IPTransportProtocol");
				if (!protocol_string.has_value())
				{
					std::printf(
						"\n** TcpipTransportPacketDrops **\n"
						"       <Failed to read 'IPTransportProtocol' from event record>\n");
					return;
				}

				const auto reason_string = event_message.readEventProperty(L"Reason");
				if (!reason_string.has_value())
				{
					std::printf(
						"\n** TcpipTransportPacketDrops **\n"
						"       <Failed to read 'Reason' from event record>\n");
					return;
				}

				const auto local_address_string = event_message.readEventProperty(L"LocalSockAddr");
				if (!local_address_string)
				{
					std::printf(
						"\n** TcpipTransportPacketDrops **\n"
						"       <Failed to read 'LocalSockAddr' from event record>\n");
					return;
				}
				const auto& local_address = local_address_string.value();
				wil::network::socket_address local_sockaddr;
				if (FAILED(local_sockaddr.reset_complete_address_nothrow(local_address.c_str())))
				{
					DebugBreak();
				}
				if (local_sockaddr.address_type() == NlatBroadcast || local_sockaddr.address_type() == NlatMulticast)
				{
					// ignore drops to the broadcast or multicast address - this is just noise on the wire
					// TODO: consider logging with -verbose
					return;
				}
				if (local_sockaddr.port() == 0)
				{
					const auto formatted_address = local_sockaddr.format_complete_address();
					if (local_address != formatted_address)
					{
						DebugBreak();
					}
					// ignore drops to port 0 - this is generally local broadcast traffic
					// TODO: consider logging with -verbose
					return;
				}

				std::printf(
					"\n** TcpipTransportPacketDrops **\n"
					"       Keyword %llu\n"
					"       Level %u\n"
					"       Channel %u\n"
					"       Opcode %u\n"
					"       Protocol %ls\n"
					"       Local Address %ls\n"
					"       Remote Address %ls\n"
					"       Reason %hs\n",
					event_message.getKeyword(),
					event_message.getLevel(),
					event_message.getChannel(),
					event_message.getOpcode(),
					IpProtocolToString(std::stoi(protocol_string.value())).c_str(),
					local_address.c_str(),
					event_message.readEventProperty(L"RemoteSockAddr").value_or(std::wstring(L"<etw-field-not-set>")).c_str(),
					TransportDiscardReasonToString(static_cast<InetDiscardReason>(std::stoi(reason_string.value())))
				);
			}
			else if (TcpipNetworkPacketDropEventId == event_message.getEventId())
			{
				const auto protocol_string = event_message.readEventProperty(L"IPTransportProtocol");
				if (!protocol_string.has_value())
				{
					std::printf(
						"\n** TcpipNetworkPacketDrops **\n"
						"       <Failed to read 'IPTransportProtocol' from event record>\n");
					return;
				}

				if (protocol_string == L"0" || protocol_string == L"17" || protocol_string == L"6")
				{
					// HOPOPT is noisy - ignore this
					// TODO: consider logging with -verbose
					return;
				}

				const auto address_family_string = event_message.readEventProperty(L"AddressFamily");
				if (!address_family_string.has_value())
				{
					std::printf(
						"\n** TcpipNetworkPacketDrops **\n"
						"       <Failed to read 'AddressFamily' from event record>\n");
					return;
				}

				const auto reason_string = event_message.readEventProperty(L"Reason");
				if (!reason_string.has_value())
				{
					std::printf(
						"\n** TcpipNetworkPacketDrops **\n"
						"       <Failed to read 'Reason' from event record>\n");
					return;
				}

				const auto direction_string = event_message.readEventProperty(L"PathDirection");
				if (!direction_string.has_value())
				{
					std::printf(
						"\n** TcpipNetworkPacketDrops **\n"
						"       <Failed to read 'PathDirection' from event record>\n");
					return;
				}

				std::wstring address_family;
				std::wstring source_address;
				std::wstring destination_address;
				if (address_family_string == std::wstring(L"2"))
				{
					address_family = L"IPv4";
					source_address = event_message.readEventProperty(L"Source IPv4 Address").value_or(std::wstring(L"<etw-field-not-set>"));
					destination_address = event_message.readEventProperty(L"Dest IPv4 Address").value_or(std::wstring(L"<etw-field-not-set>"));
				}
				else if (address_family_string == std::wstring(L"23"))
				{
					address_family = L"IPv6";
					source_address = event_message.readEventProperty(L"IPv6 Source Address").value_or(std::wstring(L"<etw-field-not-set>"));
					destination_address = event_message.readEventProperty(L"IPv6 Dest Address").value_or(std::wstring(L"<etw-field-not-set>"));
				}
				else
				{
					address_family = address_family_string.value();
					source_address = L"<not an IPv4 or IPv6 packet>";
					destination_address = L"<not an IPv4 or IPv6 packet>";
				}

				std::wstring direction = direction_string.value();
				if (direction_string.value() == L"0")
				{
					direction = L"Outbound";
				}
				else if (direction_string.value() == L"1")
				{
					direction = L"Inbound";
				}

				std::printf(
					"\n** TcpipNetworkPacketDrops **\n"
					"       Keyword %llu\n"
					"       Level %u\n"
					"       Channel %u\n"
					"       Opcode %u\n"
					"       Protocol %ls\n"
					"       AddressFamily %ls\n"
					"       Direction %ls\n"
					"       Source Address %ls\n"
					"       Destination Address %ls\n"
					"       Reason %hs\n"
					"       IfIndex %ls\n",
					event_message.getKeyword(),
					event_message.getLevel(),
					event_message.getChannel(),
					event_message.getOpcode(),
					IpProtocolToString(std::stoi(protocol_string.value())).c_str(),
					address_family.c_str(),
					direction.c_str(),
					source_address.c_str(),
					destination_address.c_str(),
					NetworkDiscardReasonToString(static_cast<IpDiscardReason>(std::stoi(reason_string.value()))),
					event_message.readEventProperty(L"IfIndex").value_or(std::wstring(L"<etw-field-not-set>")).c_str()
				);
			}
			else if (event_message.getEventId() == TcpipFramingPacketDrops)
			{
				std::printf(
					"\n** TcpipFramingPacketDrops **\n"
					"       Keyword %llu\n"
					"       Level %u\n"
					"       Channel %u\n"
					"       Opcode %u\n",
					event_message.getKeyword(),
					event_message.getLevel(),
					event_message.getChannel(),
					event_message.getOpcode()
				);
			}
		}
		catch (...)
		{
			std::printf("  <Failed to process TCPIP ETW event record>\n");
		}
		};

	std::printf("\n ... constructing ETW trace session for TCPIP events ...\n");
	ctl::ctEtwReader etw_reader{ callback_fn };

	constexpr GUID tcpipTraceLoggingProvider = { .Data1 = 0x2F07E2EE, .Data2 = 0x15DB, .Data3 = 0x40F1, .Data4 = {0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A} };
	// flush every 100ms to be more responsive to new events
	THROW_IF_FAILED(etw_reader.StartTraceSession(L"FwDiagnose-TCPIP", nullptr, tcpipTraceLoggingProvider));
	THROW_IF_FAILED(etw_reader.EnableTraceProvidersPerEventId(
		tcpipTraceLoggingProvider,
		{ TcpipTransportPacketDrops, TcpipNetworkPacketDropEventId, TcpipFramingPacketDrops }));

	std::printf("\n ... Subscribing to NetEvents ...\n");
	HANDLE eventsHandle{};
	const auto fwpm_subscription_error = FwpmNetEventSubscribe4(
		GetFwpmEngineHandle(),
		&subscription_info,
		[](void*, const FWPM_NET_EVENT5* event)
		{
			try
			{
				std::printf(
					"\n** NetEvent received **\n"
					"%ls"
					"%ls"
					"%ls",
					PrintNetEventType(event).c_str(),
					PrintNetEventHeader(event).c_str(),
					PrintNetEventDetailedStruct(event).c_str());

				if (event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP)
				{
					std::printf("   * Classify Drop Event\n");
					const auto& found_filter = FindFilterByFilterId(event->classifyDrop->filterId);
					std::printf(
						"     * Filter name: %ls\n"
						"     * Filter description: %ls\n",
						found_filter.name.value.c_str(),
						found_filter.description.c_str());

					if (found_filter.InvokesCallout())
					{
						std::printf(
							"     * Filter invokes callout: %ls\n",
							PrintCallout(found_filter.action_type.calloutKey).
							c_str());
					}

					const auto& found_sublayer = FindSublayer(found_filter.subLayerKey);
					std::printf(
						"     * Filter layer: %hs\n"
						"     * Filter sublayer: %ls\n",
						FwpmLayerToString(found_filter.layerKey).c_str(),
						SublayerToSimpleString(found_sublayer).c_str());
				}
			}
			catch (const std::exception& ex)
			{
				std::printf(
					"\n*** An error occurred processing a NetEvent: %hs\n",
					ex.what());
			}
		},
		nullptr, // null context
		&eventsHandle);
	THROW_IF_WIN32_ERROR_MSG(fwpm_subscription_error, "FwpmNetEventSubscribe4");

	std::printf(
		"\n"
		"**************************************************************************************\n"
		"                            Subscribed to WFP NetEvents                               \n"
		"                      ( press Ctrl-C to stop processing events )                      \n"
		"**************************************************************************************\n");

	static const wil::unique_event ctrl_event(wil::EventOptions::ManualReset);
	std::printf("\n ... Setting console control handler ...\n");
	SetConsoleCtrlHandler(
		[](DWORD) -> BOOL
		{
			ctrl_event.SetEvent();
			return TRUE;
		},
		TRUE);
	std::printf("\n ... Waiting for events ...\n");
	(void)ctrl_event.wait();

	(void)etw_reader.FlushTraceSession();
	etw_reader.StopTraceSession();

	const auto fwpm_unsubscribe_error = FwpmNetEventUnsubscribe0(GetFwpmEngineHandle(), eventsHandle);
	THROW_IF_WIN32_ERROR_MSG(fwpm_unsubscribe_error, "FwpmNetEventUnsubscribe0");
	std::printf("\n**  Exiting  **\n");
}