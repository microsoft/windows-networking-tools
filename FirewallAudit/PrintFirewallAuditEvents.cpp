#include <string>

#include "platform_headers.h"
#include "ctSockaddr.h"

HRESULT ToString(std::string& returnString, _Printf_format_string_ PCSTR pszFormat, const va_list& argsV) noexcept
try
{
    const size_t lengthRequiredWithoutNull = _vscprintf(pszFormat, argsV);
    RETURN_HR_IF(E_INVALIDARG, static_cast<int>(lengthRequiredWithoutNull) <= 0);
    returnString.resize(lengthRequiredWithoutNull, '\0');
    RETURN_IF_FAILED(StringCchVPrintfExA(returnString.data(), lengthRequiredWithoutNull + 1, nullptr, nullptr, STRSAFE_NULL_ON_FAILURE, pszFormat, argsV));
    return S_OK;
}
CATCH_RETURN()

std::string ToString(_Printf_format_string_ PCSTR pszFormat, ...)
{
    std::string result;
    va_list argsV;
    va_start(argsV, pszFormat);
    const auto hr = ToString(result, pszFormat, argsV);
    va_end(argsV);
    THROW_IF_FAILED(hr);
    return result;
}

std::string ToString(const FILETIME& filetime)
{
    // Convert the last-write time to local time.
    SYSTEMTIME stUtc{};
    FileTimeToSystemTime(&filetime, &stUtc);
    SYSTEMTIME stLocal{};
    SystemTimeToTzSpecificLocalTime(nullptr, &stUtc, &stLocal);
    // Build a string showing the date and time.
    return ToString("%02d/%02d/%d--%02d:%02d:%02d.%03d",
        stLocal.wMonth, stLocal.wDay, stLocal.wYear,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond, stLocal.wMilliseconds);
}

std::string IpProtoToString(UINT8 ipProto)
{
    switch (ipProto)
    {
        case IPPROTO_ICMP:
            return "IPPROTO_ICMP";
        case IPPROTO_IGMP:
            return "IPPROTO_IGMP";
        case IPPROTO_GGP:
            return "IPPROTO_GGP";
        case IPPROTO_IPV4:
            return "IPPROTO_IPV4";
        case IPPROTO_ST:
            return "IPPROTO_ST";
        case IPPROTO_TCP:
            return "IPPROTO_TCP";
        case IPPROTO_CBT:
            return "IPPROTO_CBT";
        case IPPROTO_EGP:
            return "IPPROTO_EGP";
        case IPPROTO_IGP:
            return "IPPROTO_IGP";
        case IPPROTO_PUP:
            return "IPPROTO_PUP";
        case IPPROTO_UDP:
            return "IPPROTO_UDP";
        case IPPROTO_IDP:
            return "IPPROTO_IDP";
        case IPPROTO_RDP:
            return "IPPROTO_RDP";
        case IPPROTO_IPV6:
            return "IPPROTO_IPV6";
        case IPPROTO_ROUTING:
            return "IPPROTO_ROUTING";
        case IPPROTO_FRAGMENT:
            return "IPPROTO_FRAGMENT";
        case IPPROTO_ESP:
            return "IPPROTO_ESP";
        case IPPROTO_AH:
            return "IPPROTO_AH";
        case IPPROTO_ICMPV6:
            return "IPPROTO_ICMPV6";
        case IPPROTO_NONE:
            return "IPPROTO_NONE";
        case IPPROTO_DSTOPTS:
            return "IPPROTO_DSTOPTS";
        case IPPROTO_ND:
            return "IPPROTO_ND";
        case IPPROTO_ICLFXBM:
            return "IPPROTO_ICLFXBM";
        case IPPROTO_PIM:
            return "IPPROTO_PIM";
        case IPPROTO_PGM:
            return "IPPROTO_PGM";
        case IPPROTO_L2TP:
            return "IPPROTO_L2TP";
        case IPPROTO_SCTP:
            return "IPPROTO_SCTP";
        case IPPROTO_RAW:
            return "IPPROTO_RAW";
        default:
            return "IPPROTO " + std::to_string(ipProto);
    }
}

PCSTR ToString(FWP_IP_VERSION version) noexcept
{
    switch (version)
    {
        case FWP_IP_VERSION_V4:
            return "IP_VERSION_V4";
        case FWP_IP_VERSION_V6:
            return "IP_VERSION_V6";
        case FWP_IP_VERSION_NONE:
            return "IP_VERSION_NONE";
        default:
            return "<unknown FWP_IP_VERSION>";
    }
}

std::string HeaderFlagsToString(UINT32 flags)
{
    if (flags == 0)
    {
	    return "0";
    }

    std::string returnString;
	if (flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
	{
		returnString += "IP_PROTOCOL_SET";
	}
	{
#define FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET  (0x00000002)
#define FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET (0x00000004)
#define FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET  (0x00000008)
#define FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET (0x00000010)
#define FWPM_NET_EVENT_FLAG_APP_ID_SET      (0x00000020)
#define FWPM_NET_EVENT_FLAG_USER_ID_SET     (0x00000040)
#define FWPM_NET_EVENT_FLAG_SCOPE_ID_SET    (0x00000080)
#define FWPM_NET_EVENT_FLAG_IP_VERSION_SET  (0x00000100)
#define FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET (0x00000200)
#define FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET  (0x00000400)
#define FWPM_NET_EVENT_FLAG_ENTERPRISE_ID_SET (0x00000800)
#define FWPM_NET_EVENT_FLAG_POLICY_FLAGS_SET (0x00001000)
#define FWPM_NET_EVENT_FLAG_EFFECTIVE_NAME_SET (0x00002000)
	}
}

PCSTR ToString(FWP_AF af) noexcept
{
    switch (af)
    {
        case FWP_AF_NONE:
            return "AF_NONE";
        case FWP_AF_INET:
            return "AF_INET";
        case FWP_AF_INET6:
            return "AF_INET6";
        case FWP_AF_ETHER:
            return "AF_ETHER";
        default:
            return "<unknown FWP_AF>";
    }
}

std::string ToString(const FWP_BYTE_BLOB& byteBlob)
{
    return {byteBlob.data, byteBlob.data + byteBlob.size};
}

std::string ToString(_In_ SID* sid)
{
    if (!sid)
    {
        return "null";
    }

    wil::unique_hlocal_ansistring outputSid;
    if (!ConvertSidToStringSidA(sid, outputSid.addressof()))
    {
        return "null";
    }
    return outputSid.get();
}

PCSTR PrintFileHeader() noexcept
{
    return "eventName,timeStamp,flags,ipVersion,localAddress,remoteAddress,ipProtocol,appId,userId,addressFamily,packageSid,enterpriseId,policyFlags,effectiveName";
}

std::string PrintEventHeader(FWPM_NET_EVENT_HEADER3 header, _In_ PCSTR eventName)
{
    ctl::ctSockaddr localAddr;
    ctl::ctSockaddr remoteAddr;

    if (header.ipVersion == FWP_IP_VERSION_V4)
    {
        in_addr v4Addr{};
        localAddr.reset(AF_INET);
        v4Addr.S_un.S_addr = header.localAddrV4;
        localAddr.setAddress(&v4Addr);

        remoteAddr.reset(AF_INET);
        v4Addr.S_un.S_addr = header.remoteAddrV4;
        remoteAddr.setAddress(&v4Addr);
    }
    else if (header.ipVersion == FWP_IP_VERSION_V6)
    {
        in6_addr v6Addr{};
        static_assert(sizeof v6Addr.u.Byte == sizeof header.localAddrV6.byteArray16);

        localAddr.reset(AF_INET6);
        memcpy(&v6Addr.u.Byte, header.localAddrV6.byteArray16, sizeof v6Addr.u.Byte);
        localAddr.setAddress(&v6Addr);
	    localAddr.setScopeId(header.scopeId);

        remoteAddr.reset(AF_INET6);
        memcpy(&v6Addr.u.Byte, header.remoteAddrV6.byteArray16, sizeof v6Addr.u.Byte);
        remoteAddr.setAddress(&v6Addr);
    }

    localAddr.setPort(header.localPort, ctl::ByteOrder::NetworkOrder);
    remoteAddr.setPort(header.remotePort, ctl::ByteOrder::NetworkOrder);

    char localaddressString[ctl::ctSockaddr::FixedStringLength]{};
    localAddr.writeAddress(localaddressString);
    char remoteAddressString[ctl::ctSockaddr::FixedStringLength]{};
    remoteAddr.writeAddress(remoteAddressString);

    // format:
    // eventName,timeStamp,flags,ipVersion,localAddress,remoteAddress,ipProtocol,appId,userId,addressFamily,packageSid,enterpriseId,policyFlags,effectiveName
    return ToString("%hs,%hs,%lu,%hs,%hs,%hs,%hs,%hs,%hs,%hs,%hs,%ws,%llu,%hs",
        eventName,
        ToString(header.timeStamp).c_str(),
        header.flags,
        ToString(header.ipVersion),
        localaddressString,
        remoteAddressString,
        IpProtoToString(header.ipProtocol).c_str(),
        ToString(header.appId).c_str(),
        ToString(header.userId).c_str(),
        ToString(header.addressFamily),
        ToString(header.packageSid).c_str(),
        header.enterpriseId == nullptr ? L"null" : header.enterpriseId,
        header.policyFlags,
        std::string(header.effectiveName.data, header.effectiveName.data + header.effectiveName.size).c_str());

    /*
        FILETIME timeStamp;
        UINT32 flags;
        FWP_IP_VERSION ipVersion;
        UINT8 ipProtocol;
        union
            {
            UINT32 localAddrV4;
            FWP_BYTE_ARRAY16 localAddrV6;

            } 	;
        union
            {
            UINT32 remoteAddrV4;
            FWP_BYTE_ARRAY16 remoteAddrV6;
            } 	;
        UINT16 localPort;
        UINT16 remotePort;
        UINT32 scopeId;
        FWP_BYTE_BLOB appId;
        SID *userId;
        FWP_AF addressFamily;
        SID *packageSid;
        wchar_t *enterpriseId;
        UINT64 policyFlags;
        FWP_BYTE_BLOB effectiveName;
     */
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IKEEXT_MM_FAILURE2*)
{
    constexpr auto* ikeMmFailure = "IKEEXT_MM_FAILURE";
    return PrintEventHeader(header, ikeMmFailure);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IKEEXT_QM_FAILURE1*)
{
    constexpr auto* ikeQmFailure = "IKEEXT_QM_FAILURE";
    return PrintEventHeader(header, ikeQmFailure);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IKEEXT_EM_FAILURE1*)
{
    constexpr auto* ikeEmFailure = "IKEEXT_EM_FAILURE";
    return PrintEventHeader(header, ikeEmFailure);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CLASSIFY_DROP2*)
{
    /*
     * Detailed information from the eventPayload
     *
    UINT64 filterId;
    UINT16 layerId;
    INT32 failureStatus; // empty
    FWP_DIRECTION direction; // empty
    UINT32 reauthReason;
    UINT32 originalProfile;
    UINT32 currentProfile;
    UINT32 msFwpDirection;
    BOOL isLoopback;
    FWP_BYTE_BLOB vSwitchId;
    UINT32 vSwitchSourcePort;
    UINT32 vSwitchDestinationPort;
    IPSEC_SA_SPI spi; // empty
    SOCKADDR publicHost; // empty
    SOCKADDR internalHost; // empty
    FWPM_APPC_NETWORK_CAPABILITY_TYPE networkCapabilityId; // empty
    FWP_BYTE_ARRAY6 localMacAddr; // empty
    FWP_BYTE_ARRAY6 remoteMacAddr; // empty
    UINT32 mediaType; // empty
    UINT32 ifType; // empty
    UINT16 etherType; // empty
    UINT32 ndisPortNumber; // empty
    UINT32 reserved; // empty
    UINT16 vlanTag; // empty
    UINT64 ifLuid; // empty
    */

    constexpr auto* classifyDrop = "CLASSIFY_DROP";
    return PrintEventHeader(header, classifyDrop);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IPSEC_KERNEL_DROP0*)
{
    /*
     * Detailed information from the eventPayload
     *
    UINT64 filterId;
    UINT16 layerId;
    INT32 failureStatus;
    FWP_DIRECTION direction;
    UINT32 reauthReason; // empty
    UINT32 originalProfile; // empty
    UINT32 currentProfile; // empty
    UINT32 msFwpDirection; // empty
    BOOL isLoopback; // empty
    FWP_BYTE_BLOB vSwitchId; // empty
    UINT32 vSwitchSourcePort; // empty
    UINT32 vSwitchDestinationPort; // empty
    IPSEC_SA_SPI spi;
    SOCKADDR publicHost; // empty
    SOCKADDR internalHost; // empty
    FWPM_APPC_NETWORK_CAPABILITY_TYPE networkCapabilityId; // empty
    FWP_BYTE_ARRAY6 localMacAddr; // empty
    FWP_BYTE_ARRAY6 remoteMacAddr; // empty
    UINT32 mediaType; // empty
    UINT32 ifType; // empty
    UINT16 etherType; // empty
    UINT32 ndisPortNumber; // empty
    UINT32 reserved; // empty
    UINT16 vlanTag; // empty
    UINT64 ifLuid; // empty
    */

    constexpr auto* ipsecDrop = "IPSEC_KERNEL_DROP";
    return PrintEventHeader(header, ipsecDrop);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IPSEC_DOSP_DROP0*)
{
    /*
     * Detailed information from the eventPayload
     *
    UINT64 filterId; // empty
    UINT16 layerId; // empty
    INT32 failureStatus;
    FWP_DIRECTION direction;
    UINT32 reauthReason; // empty
    UINT32 originalProfile; // empty
    UINT32 currentProfile; // empty
    UINT32 msFwpDirection; // empty
    BOOL isLoopback; // empty
    FWP_BYTE_BLOB vSwitchId; // empty
    UINT32 vSwitchSourcePort; // empty
    UINT32 vSwitchDestinationPort; // empty
    IPSEC_SA_SPI spi; // empty
    SOCKADDR publicHost;
    SOCKADDR internalHost;
    FWPM_APPC_NETWORK_CAPABILITY_TYPE networkCapabilityId; // empty
    FWP_BYTE_ARRAY6 localMacAddr; // empty
    FWP_BYTE_ARRAY6 remoteMacAddr; // empty
    UINT32 mediaType; // empty
    UINT32 ifType; // empty
    UINT16 etherType; // empty
    UINT32 ndisPortNumber; // empty
    UINT32 reserved; // empty
    UINT16 vlanTag; // empty
    UINT64 ifLuid; // empty

    FWP_IP_VERSION ipVersion;
    union
    {
        UINT32 publicHostV4Addr;
        UINT8 publicHostV6Addr[16];
    };
    union
    {
        UINT32 internalHostV4Addr;
        UINT8 internalHostV6Addr[16];
    };
    */

    constexpr auto* dospDrop = "IPSEC_DOSP_DROP";
    return PrintEventHeader(header, dospDrop);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CAPABILITY_DROP0*)
{
    /*
     * Detailed information from the eventPayload
     *
    UINT64 filterId;
    UINT16 layerId; // empty
    INT32 failureStatus; // empty
    FWP_DIRECTION direction; // empty
    UINT32 reauthReason; // empty
    UINT32 originalProfile; // empty
    UINT32 currentProfile; // empty
    UINT32 msFwpDirection; // empty
    BOOL isLoopback;
    FWP_BYTE_BLOB vSwitchId; // empty
    UINT32 vSwitchSourcePort; // empty
    UINT32 vSwitchDestinationPort; // empty
    IPSEC_SA_SPI spi; // empty
    SOCKADDR publicHost; // empty
    SOCKADDR internalHost; // empty
    FWPM_APPC_NETWORK_CAPABILITY_TYPE networkCapabilityId;
    FWP_BYTE_ARRAY6 localMacAddr; // empty
    FWP_BYTE_ARRAY6 remoteMacAddr; // empty
    UINT32 mediaType; // empty
    UINT32 ifType; // empty
    UINT16 etherType; // empty
    UINT32 ndisPortNumber; // empty
    UINT32 reserved; // empty
    UINT16 vlanTag; // empty
    UINT64 ifLuid; // empty
    */

    constexpr auto* capabilityDrop = "CAPABILITY_DROP";
    return PrintEventHeader(header, capabilityDrop);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CLASSIFY_DROP_MAC0*)
{
    /*
     * Detailed information from the eventPayload
     *
    UINT64 filterId;
    UINT16 layerId;
    INT32 failureStatus; // empty
    FWP_DIRECTION direction; // empty
    UINT32 reauthReason;
    UINT32 originalProfile;
    UINT32 currentProfile;
    UINT32 msFwpDirection;
    BOOL isLoopback;
    FWP_BYTE_BLOB vSwitchId;
    UINT32 vSwitchSourcePort;
    UINT32 vSwitchDestinationPort;
    IPSEC_SA_SPI spi; // empty
    SOCKADDR publicHost; // empty
    SOCKADDR internalHost; // empty
    FWPM_APPC_NETWORK_CAPABILITY_TYPE networkCapabilityId; // empty
    FWP_BYTE_ARRAY6 localMacAddr;
    FWP_BYTE_ARRAY6 remoteMacAddr;
    UINT32 mediaType;
    UINT32 ifType;
    UINT16 etherType;
    UINT32 ndisPortNumber;
    UINT32 reserved;
    UINT16 vlanTag;
    UINT64 ifLuid;
    */

    constexpr auto* classifyDropMac = "CLASSIFY_DROP_MAC";
    return PrintEventHeader(header, classifyDropMac);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CLASSIFY_ALLOW0*)
{
    constexpr auto* classifyAllow = "CLASSIFY_ALLOW";
    return PrintEventHeader(header, classifyAllow);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CAPABILITY_ALLOW0*)
{
    constexpr auto* capabilityAllow = "CAPABILITY_ALLOW";
    return PrintEventHeader(header, capabilityAllow);
}

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0*)
{
    constexpr auto* lpmPacketArrival = "LPM_PACKET_ARRIVAL";
    return PrintEventHeader(header, lpmPacketArrival);
}
