// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <windows.h>
#include <fwpmtypes.h>


void ListenForWfpNetEvents();

std::wstring PrintNetEventType(const FWPM_NET_EVENT5* net_event);
std::wstring PrintNetEventHeader(const FWPM_NET_EVENT5* net_event);

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
