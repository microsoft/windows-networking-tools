#pragma once
#include <fwpmtypes.h>
#include <string>

PCSTR PrintFileHeader() noexcept;

std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IKEEXT_MM_FAILURE2*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IKEEXT_QM_FAILURE1*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IKEEXT_EM_FAILURE1*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CLASSIFY_DROP2*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IPSEC_KERNEL_DROP0*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_IPSEC_DOSP_DROP0*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CAPABILITY_DROP0*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CLASSIFY_DROP_MAC0*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CLASSIFY_ALLOW0*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_CAPABILITY_ALLOW0*);
std::string PrintFirewallAuditEvent(FWPM_NET_EVENT_HEADER3 header, FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0*);