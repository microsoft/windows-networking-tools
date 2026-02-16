#include <optional>
#include "IpProperties.h"

#include <wil/stl.h>
#include <wil/network.h>
#include <wil/resource.h>

#include "FwDiagnose.h"

struct IpAddressDetails
{
	explicit IpAddressDetails(MIB_UNICASTIPADDRESS_ROW row) noexcept
	{
		type = Unicast;
		address.unicast_address_row = row;
	}
	explicit IpAddressDetails(MIB_MULTICASTIPADDRESS_ROW row) noexcept
	{
		type = Multicast;
		address.multicast_address_row = row;
	}
	explicit IpAddressDetails(MIB_ANYCASTIPADDRESS_ROW row) noexcept
	{
		type = Anycast;
		address.anycast_address_row = row;
	}

	enum AddressType
	{
		Unicast,
		Multicast,
		Anycast
	} type = Unicast;

	union AddressField
	{
		MIB_UNICASTIPADDRESS_ROW unicast_address_row = {};
		MIB_MULTICASTIPADDRESS_ROW multicast_address_row;
		MIB_ANYCASTIPADDRESS_ROW anycast_address_row;
	} address;
};

struct IpInterfaceDetails
{
	explicit IpInterfaceDetails(const MIB_IF_ROW2& row) noexcept
	{
		interface_luid = row.InterfaceLuid;
		l2_interface_row = row;
	}
	explicit IpInterfaceDetails(const MIB_IPINTERFACE_ROW& row) noexcept
	{
		interface_luid = row.InterfaceLuid;
		l3_interface_row = row;
	}

	NET_LUID interface_luid = {};
	std::optional<MIB_IPINTERFACE_ROW> l3_interface_row = { std::nullopt };
	std::optional<MIB_IF_ROW2> l2_interface_row = { std::nullopt };

	std::vector<IpAddressDetails> addresses;
};

static std::vector<IpInterfaceDetails> g_ip_details;

static IpInterfaceDetails& FindExistingInterfaceObject(const NET_LUID& luid)
{
	for (auto& details : g_ip_details)
	{
		if (details.interface_luid.Value == luid.Value)
		{
			return details;
		}
	}
	THROW_WIN32(ERROR_NOT_FOUND);
}

static IpInterfaceDetails& FindExistingInterfaceObject(const in_addr& address)
{
	for (auto& details : g_ip_details)
	{
		for (const auto& address_details : details.addresses)
		{
			if (address_details.type == IpAddressDetails::Unicast)
			{
				if (address_details.address.unicast_address_row.Address.si_family == AF_INET &&
					address_details.address.unicast_address_row.Address.Ipv4.sin_addr.s_addr == address.s_addr)
				{
					return details;
				}
			}
			else if (address_details.type == IpAddressDetails::Multicast)
			{
				if (address_details.address.multicast_address_row.Address.si_family == AF_INET &&
					address_details.address.multicast_address_row.Address.Ipv4.sin_addr.s_addr == address.s_addr)
				{
					return details;
				}
			}
			else if (address_details.type == IpAddressDetails::Anycast)
			{
				if (address_details.address.anycast_address_row.Address.si_family == AF_INET &&
					address_details.address.anycast_address_row.Address.Ipv4.sin_addr.s_addr == address.s_addr)
				{
					return details;
				}
			}
		}
	}
	THROW_WIN32(ERROR_NOT_FOUND);
}
static IpInterfaceDetails& FindExistingInterfaceObject(const in6_addr& address)
{
	for (auto& details : g_ip_details)
	{
		for (const auto& address_details : details.addresses)
		{
			if (address_details.type == IpAddressDetails::Unicast)
			{
				if (address_details.address.unicast_address_row.Address.si_family == AF_INET6 &&
					(0 == memcmp(
						&address_details.address.unicast_address_row.Address.Ipv6.sin6_addr,
						&address,
						sizeof(in6_addr))))
				{
					return details;
				}
			}
			else if (address_details.type == IpAddressDetails::Multicast)
			{
				if (address_details.address.multicast_address_row.Address.si_family == AF_INET6 &&
					(0 == memcmp(
						&address_details.address.multicast_address_row.Address.Ipv6.sin6_addr,
						&address,
						sizeof(in6_addr))))
				{
					return details;
				}
			}
			else if (address_details.type == IpAddressDetails::Anycast)
			{
				if (address_details.address.anycast_address_row.Address.si_family == AF_INET6 &&
					(0 == memcmp(
						&address_details.address.anycast_address_row.Address.Ipv6.sin6_addr,
						&address,
						sizeof(in6_addr))))
				{
					return details;
				}
			}
		}
	}
	THROW_WIN32(ERROR_NOT_FOUND);
}

using unique_if_table = wil::unique_any<PMIB_IF_TABLE2, decltype(&FreeMibTable), FreeMibTable>;
using unique_ip_interface_table = wil::unique_any<PMIB_IPINTERFACE_TABLE, decltype(&FreeMibTable), FreeMibTable>;
using unique_ip_unicast_address_table = wil::unique_any<PMIB_UNICASTIPADDRESS_TABLE, decltype(&FreeMibTable), FreeMibTable>;
using unique_ip_multicast_address_table = wil::unique_any<PMIB_MULTICASTIPADDRESS_TABLE, decltype(&FreeMibTable), FreeMibTable>;
using unique_ip_anycast_address_table = wil::unique_any<PMIB_ANYCASTIPADDRESS_TABLE, decltype(&FreeMibTable), FreeMibTable>;

// Load IP Interface information to enable mapping of addresses with interfaces
void LoadIpProperties() noexcept
try
{
	unique_if_table ifTable;
	THROW_IF_WIN32_ERROR_MSG(GetIfTable2(ifTable.addressof()), "GetIfTable2");
	for (const auto& ifRow : wil::make_range(ifTable.get()->Table, ifTable.get()->Table + ifTable.get()->NumEntries))
	{
		bool updated = false;
		for (auto& details : g_ip_details)
		{
			if (details.interface_luid.Value == ifRow.InterfaceLuid.Value)
			{
				updated = true;
				details.l2_interface_row = ifRow;
				break;
			}
		}
		if (!updated)
		{
			g_ip_details.emplace_back(ifRow);
		}
	}

	unique_ip_interface_table ipInterfaceTable;
	THROW_IF_WIN32_ERROR_MSG(GetIpInterfaceTable(AF_UNSPEC, ipInterfaceTable.addressof()), "GetIpInterfaceTable");
	for (const auto& ipRow : wil::make_range(ipInterfaceTable.get()->Table, ipInterfaceTable.get()->Table + ipInterfaceTable.get()->NumEntries))
	{
		bool updated = false;
		for (auto& details : g_ip_details)
		{
			if (details.interface_luid.Value == ipRow.InterfaceLuid.Value)
			{
				updated = true;
				details.l3_interface_row = ipRow;
				break;
			}
		}
		if (!updated)
		{
			g_ip_details.emplace_back(ipRow);
		}
	}

	unique_ip_unicast_address_table ipUnicastAddressTable;
	THROW_IF_WIN32_ERROR_MSG(GetUnicastIpAddressTable(AF_UNSPEC, ipUnicastAddressTable.addressof()), "GetUnicastIpAddressTable");
	for (const auto& ipUnicastAddressRow : wil::make_range(ipUnicastAddressTable.get()->Table, ipUnicastAddressTable.get()->Table + ipUnicastAddressTable.get()->NumEntries))
	{
		FindExistingInterfaceObject(ipUnicastAddressRow.InterfaceLuid).addresses.emplace_back(ipUnicastAddressRow);
	}

	unique_ip_multicast_address_table ipMulticastAddressTable;
	THROW_IF_WIN32_ERROR_MSG(GetMulticastIpAddressTable(AF_UNSPEC, ipMulticastAddressTable.addressof()), "GetMulticastIpAddressTable");
	for (const auto& ipMulticastAddressRow : wil::make_range(ipMulticastAddressTable.get()->Table, ipMulticastAddressTable.get()->Table + ipMulticastAddressTable.get()->NumEntries))
	{
		FindExistingInterfaceObject(ipMulticastAddressRow.InterfaceLuid).addresses.emplace_back(ipMulticastAddressRow);
	}

	unique_ip_anycast_address_table ipAnycastAddressTable;
	THROW_IF_WIN32_ERROR_MSG(GetAnycastIpAddressTable(AF_UNSPEC, ipAnycastAddressTable.addressof()), "GetAnycastIpAddressTable");
	for (const auto& ipAnycastAddressRow : wil::make_range(ipAnycastAddressTable.get()->Table, ipAnycastAddressTable.get()->Table + ipAnycastAddressTable.get()->NumEntries))
	{
		FindExistingInterfaceObject(ipAnycastAddressRow.InterfaceLuid).addresses.emplace_back(ipAnycastAddressRow);
	}
}
catch (const std::exception& e)
{
	std::printf("\n*** An error occurred loading IP properties: %hs\n", e.what());
}

std::wstring PrintIPInterfaceInfo(int space_count, const in_addr& local_addr) noexcept
try
{
	std::wstring return_string;

	const auto& found_interface = FindExistingInterfaceObject(local_addr);
	if (found_interface.l2_interface_row.has_value())
	{
		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(L"Interface: %ls (%ls)\n", found_interface.l2_interface_row->Alias, found_interface.l2_interface_row->Description);

		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(
			L"LUID: 0x%llx, Index: %lu, Guid: %ls\n",
			found_interface.interface_luid.Value,
			found_interface.l2_interface_row->InterfaceIndex,
			GuidToString(found_interface.l2_interface_row->InterfaceGuid).c_str());

		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(
			L"IfType: %hs (%hs)",
			std::to_wstring(found_interface.l2_interface_row->Type).c_str(),
			IfTypeToString(found_interface.l2_interface_row->Type).c_str());
		if (found_interface.l2_interface_row->Type == IF_TYPE_TUNNEL)
		{
			return_string += wil::str_printf<std::wstring>(
				L" , Tunnel Type: %hs (%hs)",
				std::to_wstring(found_interface.l2_interface_row->TunnelType).c_str(),
				IfTunnelTypeToString(found_interface.l2_interface_row->TunnelType).c_str());
		}
		return_string += L"\n";
	}
	else if (found_interface.l3_interface_row.has_value())
	{
		return_string.insert(return_string.size(), space_count, L' ');
		return_string += L"Interface: (no L2 information available)\n";

		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(
			L"LUID: 0x%llx, Index: %lu\n",
			found_interface.interface_luid.Value,
			found_interface.l3_interface_row->InterfaceIndex);
	}
	else
	{
		return_string.insert(return_string.size(), space_count, L' ');
		return_string += L"Interface: (address is not assigned to a local interface)\n";
	}

	return return_string;
}
catch (...)
{
	std::wstring return_string;
	return_string.insert(return_string.size(), space_count, L' ');
	return_string.append(L"Interface: (address is not assigned to a local interface)\n");
	return return_string;
}

std::wstring PrintIPInterfaceInfo(int space_count, const in6_addr& local_addr) noexcept
try
{
	std::wstring return_string;
	return_string.append(L" ", space_count);

	const auto& found_interface = FindExistingInterfaceObject(local_addr);
	if (found_interface.l2_interface_row.has_value())
	{
		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(L"Interface: %ls (%ls)\n", found_interface.l2_interface_row->Alias, found_interface.l2_interface_row->Description);

		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(
			L"LUID: 0x%llx (Index: %lu, Guid: %ls)\n",
			found_interface.interface_luid.Value,
			found_interface.l2_interface_row->InterfaceIndex,
			GuidToString(found_interface.l2_interface_row->InterfaceGuid).c_str());

		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(
			L"IfType: %hs (%hs)",
			std::to_wstring(found_interface.l2_interface_row->Type).c_str(),
			IfTypeToString(found_interface.l2_interface_row->Type).c_str());
		if (found_interface.l2_interface_row->Type == IF_TYPE_TUNNEL)
		{
			return_string += wil::str_printf<std::wstring>(
				L" , Tunnel Type: %hs (%hs)",
				std::to_wstring(found_interface.l2_interface_row->TunnelType).c_str(),
				IfTunnelTypeToString(found_interface.l2_interface_row->TunnelType).c_str());
		}
		return_string += L"\n";
	}
	else if (found_interface.l3_interface_row.has_value())
	{
		return_string.insert(return_string.size(), space_count, L' ');
		return_string += L"Interface: (no L2 information available)\n";

		return_string.insert(return_string.size(), space_count, L' ');
		return_string += wil::str_printf<std::wstring>(
			L"LUID: 0x%llx (Index: %lu)\n",
			found_interface.interface_luid.Value,
			found_interface.l3_interface_row->InterfaceIndex);
	}
	else
	{
		return_string.insert(return_string.size(), space_count, L' ');
		return_string += L"Interface: (address is not assigned to a local interface)\n";
	}

	return return_string;
}
catch (...)
{
	std::wstring return_string;
	return_string.insert(return_string.size(), space_count, L' ');
	return_string.append(L"Interface: (address is not assigned to a local interface)\n");
	return return_string;
}

std::string IfTypeToString(ULONG ifType)
{
	switch (ifType)
	{
	case IF_TYPE_OTHER: return "OTHER";
	case IF_TYPE_REGULAR_1822: return "REGULAR_1822";
	case IF_TYPE_HDH_1822: return "HDH_1822";
	case IF_TYPE_DDN_X25: return "DDN_X25";
	case IF_TYPE_RFC877_X25: return "RFC877_X25";
	case IF_TYPE_ETHERNET_CSMACD: return "ETHERNET";
	case IF_TYPE_IS088023_CSMACD: return "IS088023_CSMACD";
	case IF_TYPE_ISO88024_TOKENBUS: return "ISO88024_TOKENBUS";
	case IF_TYPE_ISO88025_TOKENRING: return "ISO88025_TOKENRING";
	case IF_TYPE_ISO88026_MAN: return "ISO88026_MAN";
	case IF_TYPE_STARLAN: return "STARLAN";
	case IF_TYPE_PROTEON_10MBIT: return "PROTEON_10MBIT";
	case IF_TYPE_PROTEON_80MBIT: return "PROTEON_80MBIT";
	case IF_TYPE_HYPERCHANNEL: return "HYPERCHANNEL";
	case IF_TYPE_FDDI: return "FDDI";
	case IF_TYPE_LAP_B: return "LAP_B";
	case IF_TYPE_SDLC: return "SDLC";
	case IF_TYPE_DS1: return "DS1";
	case IF_TYPE_E1: return "E1";
	case IF_TYPE_BASIC_ISDN: return "BASIC_ISDN";
	case IF_TYPE_PRIMARY_ISDN: return "PRIMARY_ISDN";
	case IF_TYPE_PROP_POINT2POINT_SERIAL: return "PROP_POINT2POINT_SERIAL";
	case IF_TYPE_PPP: return "PPP";
	case IF_TYPE_SOFTWARE_LOOPBACK: return "SOFTWARE_LOOPBACK";
	case IF_TYPE_EON: return "EON";
	case IF_TYPE_ETHERNET_3MBIT: return "ETHERNET_3MBIT";
	case IF_TYPE_NSIP: return "NSIP";
	case IF_TYPE_SLIP: return "SLIP";
	case IF_TYPE_ULTRA: return "ULTRA";
	case IF_TYPE_DS3: return "DS3";
	case IF_TYPE_SIP: return "SIP";
	case IF_TYPE_FRAMERELAY: return "FRAMERELAY";
	case IF_TYPE_RS232: return "RS232";
	case IF_TYPE_PARA: return "PARA";
	case IF_TYPE_ARCNET: return "ARCNET";
	case IF_TYPE_ARCNET_PLUS: return "ARCNET_PLUS";
	case IF_TYPE_ATM: return "ATM";
	case IF_TYPE_MIO_X25: return "MIO_X25";
	case IF_TYPE_SONET: return "SONET";
	case IF_TYPE_X25_PLE: return "X25_PLE";
	case IF_TYPE_ISO88022_LLC: return "ISO88022_LLC";
	case IF_TYPE_LOCALTALK: return "LOCALTALK";
	case IF_TYPE_SMDS_DXI: return "SMDS_DXI";
	case IF_TYPE_FRAMERELAY_SERVICE: return "FRAMERELAY_SERVICE";
	case IF_TYPE_V35: return "V35";
	case IF_TYPE_HSSI: return "HSSI";
	case IF_TYPE_HIPPI: return "HIPPI";
	case IF_TYPE_MODEM: return "MODEM";
	case IF_TYPE_AAL5: return "AAL5";
	case IF_TYPE_SONET_PATH: return "SONET_PATH";
	case IF_TYPE_SONET_VT: return "SONET_VT";
	case IF_TYPE_SMDS_ICIP: return "SMDS_ICIP";
	case IF_TYPE_PROP_VIRTUAL: return "PROP_VIRTUAL";
	case IF_TYPE_PROP_MULTIPLEXOR: return "PROP_MULTIPLEXOR";
	case IF_TYPE_IEEE80212: return "IEEE80212";
	case IF_TYPE_FIBRECHANNEL: return "FIBRECHANNEL";
	case IF_TYPE_HIPPIINTERFACE: return "HIPPIINTERFACE";
	case IF_TYPE_FRAMERELAY_INTERCONNECT: return "FRAMERELAY_INTERCONNECT";
	case IF_TYPE_AFLANE_8023: return "AFLANE_8023";
	case IF_TYPE_AFLANE_8025: return "AFLANE_8025";
	case IF_TYPE_CCTEMUL: return "CCTEMUL";
	case IF_TYPE_FASTETHER: return "FASTETHER";
	case IF_TYPE_ISDN: return "ISDN";
	case IF_TYPE_V11: return "V11";
	case IF_TYPE_V36: return "V36";
	case IF_TYPE_G703_64K: return "G703_64K";
	case IF_TYPE_G703_2MB: return "G703_2MB";
	case IF_TYPE_QLLC: return "QLLC";
	case IF_TYPE_FASTETHER_FX: return "FASTETHER_FX";
	case IF_TYPE_CHANNEL: return "CHANNEL";
	case IF_TYPE_IEEE80211: return "IEEE80211 (Wi-Fi)";
	case IF_TYPE_IBM370PARCHAN: return "IBM370PARCHAN";
	case IF_TYPE_ESCON: return "ESCON";
	case IF_TYPE_DLSW: return "DLSW";
	case IF_TYPE_ISDN_S: return "ISDN_S";
	case IF_TYPE_ISDN_U: return "ISDN_U";
	case IF_TYPE_LAP_D: return "LAP_D";
	case IF_TYPE_IPSWITCH: return "IPSWITCH";
	case IF_TYPE_RSRB: return "RSRB";
	case IF_TYPE_ATM_LOGICAL: return "ATM_LOGICAL";
	case IF_TYPE_DS0: return "DS0";
	case IF_TYPE_DS0_BUNDLE: return "DS0_BUNDLE";
	case IF_TYPE_BSC: return "BSC";
	case IF_TYPE_ASYNC: return "ASYNC";
	case IF_TYPE_CNR: return "CNR";
	case IF_TYPE_ISO88025R_DTR: return "ISO88025R_DTR";
	case IF_TYPE_EPLRS: return "EPLRS";
	case IF_TYPE_ARAP: return "ARAP";
	case IF_TYPE_PROP_CNLS: return "PROP_CNLS";
	case IF_TYPE_HOSTPAD: return "HOSTPAD";
	case IF_TYPE_TERMPAD: return "TERMPAD";
	case IF_TYPE_FRAMERELAY_MPI: return "FRAMERELAY_MPI";
	case IF_TYPE_X213: return "X213";
	case IF_TYPE_ADSL: return "ADSL";
	case IF_TYPE_RADSL: return "RADSL";
	case IF_TYPE_SDSL: return "SDSL";
	case IF_TYPE_VDSL: return "VDSL";
	case IF_TYPE_ISO88025_CRFPRINT: return "ISO88025_CRFPRINT";
	case IF_TYPE_MYRINET: return "MYRINET";
	case IF_TYPE_VOICE_EM: return "VOICE_EM";
	case IF_TYPE_VOICE_FXO: return "VOICE_FXO";
	case IF_TYPE_VOICE_FXS: return "VOICE_FXS";
	case IF_TYPE_VOICE_ENCAP: return "VOICE_ENCAP";
	case IF_TYPE_VOICE_OVERIP: return "VOICE_OVERIP";
	case IF_TYPE_ATM_DXI: return "ATM_DXI";
	case IF_TYPE_ATM_FUNI: return "ATM_FUNI";
	case IF_TYPE_ATM_IMA: return "ATM_IMA";
	case IF_TYPE_PPPMULTILINKBUNDLE: return "PPPMULTILINKBUNDLE";
	case IF_TYPE_IPOVER_CDLC: return "IPOVER_CDLC";
	case IF_TYPE_IPOVER_CLAW: return "IPOVER_CLAW";
	case IF_TYPE_STACKTOSTACK: return "STACKTOSTACK";
	case IF_TYPE_VIRTUALIPADDRESS: return "VIRTUALIPADDRESS";
	case IF_TYPE_MPC: return "MPC";
	case IF_TYPE_IPOVER_ATM: return "IPOVER_ATM";
	case IF_TYPE_ISO88025_FIBER: return "ISO88025_FIBER";
	case IF_TYPE_TDLC: return "TDLC";
	case IF_TYPE_GIGABITETHERNET: return "GIGABITETHERNET";
	case IF_TYPE_HDLC: return "HDLC";
	case IF_TYPE_LAP_F: return "LAP_F";
	case IF_TYPE_V37: return "V37";
	case IF_TYPE_X25_MLP: return "X25_MLP";
	case IF_TYPE_X25_HUNTGROUP: return "X25_HUNTGROUP";
	case IF_TYPE_TRANSPHDLC: return "TRANSPHDLC";
	case IF_TYPE_INTERLEAVE: return "INTERLEAVE";
	case IF_TYPE_FAST: return "FAST";
	case IF_TYPE_IP: return "IP";
	case IF_TYPE_DOCSCABLE_MACLAYER: return "DOCSCABLE_MACLAYER";
	case IF_TYPE_DOCSCABLE_DOWNSTREAM: return "DOCSCABLE_DOWNSTREAM";
	case IF_TYPE_DOCSCABLE_UPSTREAM: return "DOCSCABLE_UPSTREAM";
	case IF_TYPE_A12MPPSWITCH: return "A12MPPSWITCH";
	case IF_TYPE_TUNNEL: return "TUNNEL";
	case IF_TYPE_COFFEE: return "COFFEE";
	case IF_TYPE_CES: return "CES";
	case IF_TYPE_ATM_SUBINTERFACE: return "ATM_SUBINTERFACE";
	case IF_TYPE_L2_VLAN: return "L2_VLAN";
	case IF_TYPE_L3_IPVLAN: return "L3_IPVLAN";
	case IF_TYPE_L3_IPXVLAN: return "L3_IPXVLAN";
	case IF_TYPE_DIGITALPOWERLINE: return "DIGITALPOWERLINE";
	case IF_TYPE_MEDIAMAILOVERIP: return "MEDIAMAILOVERIP";
	case IF_TYPE_DTM: return "DTM";
	case IF_TYPE_DCN: return "DCN";
	case IF_TYPE_IPFORWARD: return "IPFORWARD";
	case IF_TYPE_MSDSL: return "MSDSL";
	case IF_TYPE_IEEE1394: return "IEEE1394";
	case IF_TYPE_IF_GSN: return "IF_GSN";
	case IF_TYPE_DVBRCC_MACLAYER: return "DVBRCC_MACLAYER";
	case IF_TYPE_DVBRCC_DOWNSTREAM: return "DVBRCC_DOWNSTREAM";
	case IF_TYPE_DVBRCC_UPSTREAM: return "DVBRCC_UPSTREAM";
	case IF_TYPE_ATM_VIRTUAL: return "ATM_VIRTUAL";
	case IF_TYPE_MPLS_TUNNEL: return "MPLS_TUNNEL";
	case IF_TYPE_SRP: return "SRP";
	case IF_TYPE_VOICEOVERATM: return "VOICEOVERATM";
	case IF_TYPE_VOICEOVERFRAMERELAY: return "VOICEOVERFRAMERELAY";
	case IF_TYPE_IDSL: return "IDSL";
	case IF_TYPE_COMPOSITELINK: return "COMPOSITELINK";
	case IF_TYPE_SS7_SIGLINK: return "SS7_SIGLINK";
	case IF_TYPE_PROP_WIRELESS_P2P: return "PROP_WIRELESS_P2P";
	case IF_TYPE_FR_FORWARD: return "FR_FORWARD";
	case IF_TYPE_RFC1483: return "RFC1483";
	case IF_TYPE_USB: return "USB";
	case IF_TYPE_IEEE8023AD_LAG: return "IEEE8023AD_LAG";
	case IF_TYPE_BGP_POLICY_ACCOUNTING: return "BGP_POLICY_ACCOUNTING";
	case IF_TYPE_FRF16_MFR_BUNDLE: return "FRF16_MFR_BUNDLE";
	case IF_TYPE_H323_GATEKEEPER: return "H323_GATEKEEPER";
	case IF_TYPE_H323_PROXY: return "H323_PROXY";
	case IF_TYPE_MPLS: return "MPLS";
	case IF_TYPE_MF_SIGLINK: return "MF_SIGLINK";
	case IF_TYPE_HDSL2: return "HDSL2";
	case IF_TYPE_SHDSL: return "SHDSL";
	case IF_TYPE_DS1_FDL: return "DS1_FDL";
	case IF_TYPE_POS: return "POS";
	case IF_TYPE_DVB_ASI_IN: return "DVB_ASI_IN";
	case IF_TYPE_DVB_ASI_OUT: return "DVB_ASI_OUT";
	case IF_TYPE_PLC: return "PLC";
	case IF_TYPE_NFAS: return "NFAS";
	case IF_TYPE_TR008: return "TR008";
	case IF_TYPE_GR303_RDT: return "GR303_RDT";
	case IF_TYPE_GR303_IDT: return "GR303_IDT";
	case IF_TYPE_ISUP: return "ISUP";
	case IF_TYPE_PROP_DOCS_WIRELESS_MACLAYER: return "PROP_DOCS_WIRELESS_MACLAYER";
	case IF_TYPE_PROP_DOCS_WIRELESS_DOWNSTREAM: return "PROP_DOCS_WIRELESS_DOWNSTREAM";
	case IF_TYPE_PROP_DOCS_WIRELESS_UPSTREAM: return "PROP_DOCS_WIRELESS_UPSTREAM";
	case IF_TYPE_HIPERLAN2: return "HIPERLAN2";
	case IF_TYPE_PROP_BWA_P2MP: return "PROP_BWA_P2MP";
	case IF_TYPE_SONET_OVERHEAD_CHANNEL: return "SONET_OVERHEAD_CHANNEL";
	case IF_TYPE_DIGITAL_WRAPPER_OVERHEAD_CHANNEL: return "DIGITAL_WRAPPER_OVERHEAD_CHANNEL";
	case IF_TYPE_AAL2: return "AAL2";
	case IF_TYPE_RADIO_MAC: return "RADIO_MAC";
	case IF_TYPE_ATM_RADIO: return "ATM_RADIO";
	case IF_TYPE_IMT: return "IMT";
	case IF_TYPE_MVL: return "MVL";
	case IF_TYPE_REACH_DSL: return "REACH_DSL";
	case IF_TYPE_FR_DLCI_ENDPT: return "FR_DLCI_ENDPT";
	case IF_TYPE_ATM_VCI_ENDPT: return "ATM_VCI_ENDPT";
	case IF_TYPE_OPTICAL_CHANNEL: return "OPTICAL_CHANNEL";
	case IF_TYPE_OPTICAL_TRANSPORT: return "OPTICAL_TRANSPORT";
	case IF_TYPE_IEEE80216_WMAN: return "IEEE80216_WMAN (Cellular)";
	case IF_TYPE_WWANPP: return "WWANPP (Cellular)";
	case IF_TYPE_WWANPP2: return "WWANPP2 (Cellular)";
	case IF_TYPE_IEEE802154: return "IEEE802154";
	case IF_TYPE_XBOX_WIRELESS: return "XBOX_WIRELESS";
	default: return "(UNKNOWN - " + std::to_string(ifType) + ")";
	}
}

std::string IfTunnelTypeToString(ULONG tunnelType)
{
	switch (tunnelType)
	{
	case TUNNEL_TYPE_NONE: return "NONE";
	case TUNNEL_TYPE_OTHER: return "OTHER";
	case TUNNEL_TYPE_DIRECT: return "DIRECT";
	case TUNNEL_TYPE_6TO4: return "IPV6";
	case TUNNEL_TYPE_ISATAP: return "ISATAP";
	case TUNNEL_TYPE_TEREDO: return "TEREDO";
	case TUNNEL_TYPE_IPHTTPS: return "IPHTTPS";
	default: return "(UNKNOWN - " + std::to_string(tunnelType) + ")";
	}
}