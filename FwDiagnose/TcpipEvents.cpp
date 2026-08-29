// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <string>

#include <windows.h>
#include <Objbase.h>
#include <nldef.h>

#include "TcpipEvents.h"

#include <ctEtwReader.hpp>
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

enum FlDiscardReason {
	FlDiscardLoopbackPacket = 1,
	FlDiscardInvalidSnapHeader = 2,
	FlDiscardInvalidEthernetType = 3,
	FlDiscardInvalidPacketLength = 4,
	FlDiscardHeaderNotContiguous = 5,
	FlDiscardInvalidDestinationType = 6,
	FlDiscardAllocationFailure = 7,
	FlDiscardInterfaceRefFailure = 8,
	FlDiscardProviderRefFailure = 9,
	FlDiscardInvalidLsoInfo = 10,
	FlDiscardInvalidUsoInfo = 11,
	FlDiscardInvalidMedium = 12,
	FlDiscardInvalidArpHeader = 13,
	FlDiscardNoClientInterface = 14,
	FlDiscardTooManyNetBuffers = 15,
	FlDiscardFlsnpiClientDrop = 16,
	FlDiscardMax
};

static PCSTR TransportDiscardReasonToString(InetDiscardReason reason) noexcept
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
static PCSTR NetworkDiscardReasonToString(IpDiscardReason reason) noexcept
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
static PCSTR FramingDiscardReasonToString(FlDiscardReason reason) noexcept
{
	switch (reason)
	{
	case FlDiscardLoopbackPacket: return "FlDiscardLoopbackPacket";
	case FlDiscardInvalidSnapHeader: return "FlDiscardInvalidSnapHeader";
	case FlDiscardInvalidEthernetType: return "FlDiscardInvalidEthernetType";
	case FlDiscardInvalidPacketLength: return "FlDiscardInvalidPacketLength";
	case FlDiscardHeaderNotContiguous: return "FlDiscardHeaderNotContiguous";
	case FlDiscardInvalidDestinationType: return "FlDiscardInvalidDestinationType";
	case FlDiscardAllocationFailure: return "FlDiscardAllocationFailure";
	case FlDiscardInterfaceRefFailure: return "FlDiscardInterfaceRefFailure";
	case FlDiscardProviderRefFailure: return "FlDiscardProviderRefFailure";
	case FlDiscardInvalidLsoInfo: return "FlDiscardInvalidLsoInfo";
	case FlDiscardInvalidUsoInfo: return "FlDiscardInvalidUsoInfo";
	case FlDiscardInvalidMedium: return "FlDiscardInvalidMedium";
	case FlDiscardInvalidArpHeader: return "FlDiscardInvalidArpHeader";
	case FlDiscardNoClientInterface: return "FlDiscardNoClientInterface";
	case FlDiscardTooManyNetBuffers: return "FlDiscardTooManyNetBuffers";
	case FlDiscardFlsnpiClientDrop: return "FlDiscardFlsnpiClientDrop";
	case FlDiscardMax: return "FlDiscardMax";
	default: return "<unknown FlDiscardReason>";
	}
}

void ListenForTcpipEvents()
{
	constexpr auto TcpipTransportPacketDrops = 1214;
	constexpr auto TcpipNetworkPacketDropEventId = 1215;
	constexpr auto TcpipFramingPacketDrops = 1478;
	constexpr auto TcpSecurityRateLimit = 1025;
	constexpr auto TcpGlobalSynAttackEntry = 1055;
	constexpr auto TcpGlobalReassemblyLimitViolation = 1056;
	constexpr auto TcpGlobalConnectionRateLimitViolation = 1057;
	constexpr auto TcpGlobalLandAttackSegmentDrop = 1058;
	constexpr auto TcpGlobalSynAttackExit = 1063;
	const auto callback_fn = [](const EVENT_RECORD* pRecord) {
		try
		{
			// Process the ETW event record
			const auto event_message = ctl::ctEtwRecord(pRecord);

			switch (event_message.getEventId())
			{
			case TcpipTransportPacketDrops:
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

				// verify the local address is on this system (drop link-local broadcast traffic)
				// TODO: consider logging with -verbose
				auto local_sockaddr_without_port = local_sockaddr;
				local_sockaddr_without_port.set_port(0);
				if (local_sockaddr_without_port.family() == AF_INET6)
				{
					local_sockaddr_without_port.set_flow_info(0);
					local_sockaddr_without_port.set_scope_id(0);
				}

				// TODO: register for address change notifications
				// so I don't have to query every time
				PMIB_UNICASTIPADDRESS_TABLE unicast_ip_address_table = nullptr;
				GetUnicastIpAddressTable(AF_UNSPEC, &unicast_ip_address_table);
				const auto free_address_table = wil::scope_exit([&]() noexcept {
					if (unicast_ip_address_table)
					{
						FreeMibTable(unicast_ip_address_table);
					}
					});

				if (unicast_ip_address_table)
				{
					bool found_local_address = false;
					for (const auto& entry : wil::make_range(unicast_ip_address_table->Table, unicast_ip_address_table->Table + unicast_ip_address_table->NumEntries))
					{
						wil::network::socket_address entry_sockaddr(&entry.Address);
						if (entry_sockaddr == local_sockaddr_without_port)
						{
							found_local_address = true;
							break;
						}
					}
					if (!found_local_address)
					{
						return;
					}
				}

				std::wstring address_family;
				if (local_sockaddr.family() == AF_INET)
				{
					address_family = L"IPv4";
				}
				else if (local_sockaddr.family() == AF_INET6)
				{
					address_family = L"IPv6";
				}

                // TODO: consider a separate option for logging these reason codes:
				// InetDiscardSessionState
				// InetDiscardRst
				// InetDiscardFinWait2
				std::printf(
					"\n** TcpipTransportPacketDrops **\n"
					"       Protocol %ls\n"
					"       AddressFamily %ls\n"
					"       Direction Inbound\n"
					"       Local Address %ls\n"
					"       Remote Address %ls\n"
					"       Reason %hs\n",
					IpProtocolToString(std::stoi(protocol_string.value())).c_str(),
					address_family.c_str(),
					local_address.c_str(),
					event_message.readEventProperty(L"RemoteSockAddr").value_or(std::wstring(L"<etw-field-not-set>")).c_str(),
					TransportDiscardReasonToString(static_cast<InetDiscardReason>(std::stoi(reason_string.value())))
				);
				break;
			}
			case TcpipNetworkPacketDropEventId:
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
					"       Protocol %ls\n"
					"       AddressFamily %ls\n"
					"       Direction %ls\n"
					"       Source Address %ls\n"
					"       Destination Address %ls\n"
					"       Reason %hs\n"
					"       IfIndex %ls\n",
					IpProtocolToString(std::stoi(protocol_string.value())).c_str(),
					address_family.c_str(),
					direction.c_str(),
					source_address.c_str(),
					destination_address.c_str(),
					NetworkDiscardReasonToString(static_cast<IpDiscardReason>(std::stoi(reason_string.value()))),
					event_message.readEventProperty(L"IfIndex").value_or(std::wstring(L"<etw-field-not-set>")).c_str()
				);
				break;
			}
			case TcpipFramingPacketDrops:
			{
				const auto path_direction = event_message.readEventProperty(L"PathDirection");
				if (!path_direction.has_value())
				{
					std::printf(
						"\n** TcpipFramingPacketDrops **\n"
						"       <Failed to read 'PathDirection' from event record>\n");
					return;
				}

				const auto address_family_string = event_message.readEventProperty(L"AddressFamily");
				if (!address_family_string.has_value())
				{
					std::printf(
						"\n** TcpipFramingPacketDrops **\n"
						"       <Failed to read 'AddressFamily' from event record>\n");
					return;
				}
				auto address_family = address_family_string.value();
				if (address_family_string == std::wstring(L"2"))
				{
					address_family = L"IPv4";
				}
				else if (address_family_string == std::wstring(L"23"))
				{
					address_family = L"IPv6";
				}

				const auto direction_string = event_message.readEventProperty(L"PathDirection");
				if (!direction_string.has_value())
				{
					std::printf(
						"\n** TcpipFramingPacketDrops **\n"
						"       <Failed to read 'PathDirection' from event record>\n");
					return;
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

				const auto reason_string = event_message.readEventProperty(L"Reason");
				if (!reason_string.has_value())
				{
					std::printf(
						"\n** TcpipFramingPacketDrops **\n"
						"       <Failed to read 'Reason' from event record>\n");
					return;
				}
				if (reason_string.value() == L"3")
				{
					// ignore drops due to invalid ethernet type - this is just noise on the wire
					return;
				}

				std::printf(
					"\n** TcpipFramingPacketDrops **\n"
					"       AddressFamily %ls\n"
					"       Direction %ls\n"
					"       Interface %ls\n"
					"       Reason %hs\n",
					address_family.c_str(),
					direction.c_str(),
					event_message.readEventProperty(L"Interface").value_or(std::wstring(L"<etw-field-not-set>")).c_str(),
					FramingDiscardReasonToString(static_cast<FlDiscardReason>(std::stoi(reason_string.value())))
				);
			}

			case TcpSecurityRateLimit:
				[[fallthrough]];
			case TcpGlobalSynAttackEntry:
				[[fallthrough]];
			case TcpGlobalReassemblyLimitViolation:
				[[fallthrough]];
			case TcpGlobalConnectionRateLimitViolation:
				[[fallthrough]];
			case TcpGlobalLandAttackSegmentDrop:
				[[fallthrough]];
			case TcpGlobalSynAttackExit:
			{
				const auto SynAttacksDetected = event_message.readEventProperty(L"SynAttacksDetected");
				if (!SynAttacksDetected.has_value())
				{
					std::printf(
						"\n** TcpipSecurityEvent **\n"
						"       <Failed to read 'SynAttacksDetected' from event record>\n");
					return;
				}
				const auto ReassemblyLimitViolations = event_message.readEventProperty(L"ReassemblyLimitViolations");
				if (!ReassemblyLimitViolations.has_value())
				{
					std::printf(
						"\n** TcpipSecurityEvent **\n"
						"       <Failed to read 'ReassemblyLimitViolations' from event record>\n");
					return;
				}
				const auto ConnectionRateLimitBacklog = event_message.readEventProperty(L"ConnectionRateLimitBacklog");
				if (!ConnectionRateLimitBacklog.has_value())
				{
					std::printf(
						"\n** TcpipSecurityEvent **\n"
						"       <Failed to read 'ConnectionRateLimitBacklog' from event record>\n");
					return;
				}
				const auto ConnectionRateLimitViolations = event_message.readEventProperty(L"ConnectionRateLimitViolations");
				if (!ConnectionRateLimitViolations.has_value())
				{
					std::printf(
						"\n** TcpipSecurityEvent **\n"
						"       <Failed to read 'ConnectionRateLimitViolations' from event record>\n");
					return;
				}
				const auto LandAttackSegmentsDropped = event_message.readEventProperty(L"LandAttackSegmentsDropped");
				if (!LandAttackSegmentsDropped.has_value())
				{
					std::printf(
						"\n** TcpipSecurityEvent **\n"
						"       <Failed to read 'LandAttackSegmentsDropped' from event record>\n");
					return;
				}
				const auto ConnectionRateLimitDepth = event_message.readEventProperty(L"ConnectionRateLimitDepth");
				if (!ConnectionRateLimitDepth.has_value())
				{
					std::printf(
						"\n** TcpipSecurityEvent **\n"
						"       <Failed to read 'ConnectionRateLimitDepth' from event record>\n");
					return;
				}

				std::printf(
					"\n** TcpipSecurityEvent **\n"
					"       SynAttacksDetected %ls\n"
					"       ReassemblyLimitViolations %ls\n"
					"       ConnectionRateLimitBacklog %ls\n"
					"       ConnectionRateLimitViolations %ls\n"
					"       LandAttackSegmentsDropped %ls\n"
					"       ConnectionRateLimitDepth %ls\n",
					SynAttacksDetected.value().c_str(),
					ReassemblyLimitViolations.value().c_str(),
					ConnectionRateLimitBacklog.value().c_str(),
					ConnectionRateLimitViolations.value().c_str(),
					LandAttackSegmentsDropped.value().c_str(),
					ConnectionRateLimitDepth.value().c_str()
				);
				break;
			}
			}
		}
		CATCH_LOG()
		};

	ctl::ctEtwReader etw_reader{ callback_fn };

	constexpr GUID tcpipTraceLoggingProvider = { .Data1 = 0x2F07E2EE, .Data2 = 0x15DB, .Data3 = 0x40F1, .Data4 = {0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A} };
	// flush every 100ms to be more responsive to new events
	THROW_IF_FAILED(etw_reader.StartTraceSession(L"FwDiagnose-TCPIP", nullptr, tcpipTraceLoggingProvider));
	THROW_IF_FAILED(etw_reader.EnableTraceProvidersPerEventId(
		tcpipTraceLoggingProvider,
		{ TcpipTransportPacketDrops, TcpipNetworkPacketDropEventId, TcpipFramingPacketDrops }));

	std::printf(
		"\n"
		"**************************************************************************************\n"
		"                         Subscribed to TCPIP ETW events                              \n"
		"                      ( press Ctrl-C to stop processing events )                      \n"
		"**************************************************************************************\n");

	static const wil::unique_event ctrl_event(wil::EventOptions::ManualReset);
	SetConsoleCtrlHandler(
		[](DWORD) -> BOOL
		{
			ctrl_event.SetEvent();
			return TRUE;
		},
		TRUE);
	(void)ctrl_event.wait();

	(void)etw_reader.FlushTraceSession();
	etw_reader.StopTraceSession();
	std::printf("\n**  Exiting  **\n");
}