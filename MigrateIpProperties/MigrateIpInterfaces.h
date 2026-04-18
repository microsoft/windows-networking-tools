// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <cstdio>
#include <cstdint>
#include <string>

#include <windows.h>
#include <ws2def.h>

#include "ctWmiInstance.hpp"

#include <wil/com.h>
#include <wil/resource.h>

/*
	class MSFT_NetIPInterface : CIM_LANEndpoint
	{
	//// not recording read-only properties
		[read: ToSubClass] uint32 InterfaceIndex;
		[read: ToSubClass] string InterfaceAlias;
		[read: ToSubClass, ValueMap{"2", "23"}: ToSubClass] uint16 AddressFamily;
		[read: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 NeighborUnreachabilityDetection;
		[ValueMap{"0", "1"}: ToSubClass, read: ToSubClass] uint8 Store;
		[read: ToSubClass] uint32 ReachableTime;
		[read: ToSubClass] uint8 NeighborDiscoverySupported;
		[read: ToSubClass] uint8 ConnectionState;
		[read: ToSubClass] uint32 CompartmentId;
		[read: ToSubClass] uint32 IsolationId;
		[read: ToSubClass] uint64 LowestIfNetLuid;

	//// only recording read/write properties
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 Forwarding;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 ClampMss;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 Advertising;
		[read: ToSubClass, write: ToSubClass] uint32 NlMtu;
		[read: ToSubClass, write: ToSubClass] uint32 InterfaceMetric;
		[read: ToSubClass, write: ToSubClass] uint32 BaseReachableTime;
		[read: ToSubClass, write: ToSubClass] uint32 RetransmitTime;
		[read: ToSubClass, write: ToSubClass] uint32 DadTransmits;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1", "2", "255"}: ToSubClass] uint8 RouterDiscovery;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 ManagedAddressConfiguration;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 OtherStatefulConfiguration;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 WeakHostSend;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 WeakHostReceive;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 IgnoreDefaultRoutes;
		[read: ToSubClass, write: ToSubClass] datetime AdvertisedRouterLifetime;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 AdvertiseDefaultRoute;
		[read: ToSubClass, write: ToSubClass] uint32 CurrentHopLimit;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 ForceArpNdWolPattern;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1"}: ToSubClass] uint8 DirectedMacWolPattern;
		[read: ToSubClass, write: ToSubClass] uint8 EcnMarking;
		[read: ToSubClass, write: ToSubClass] uint8 Dhcp;
		[read: ToSubClass, write: ToSubClass] uint8 AutomaticMetric;
		[read: ToSubClass, write: ToSubClass] uint32 DadRetransmitTime;
	};
 */

struct WritableIpInterfaceProperties
{
	wil::unique_variant Forwarding{};
	wil::unique_variant ClampMss{};
	wil::unique_variant Advertising{};
	wil::unique_variant NlMtu{};
	wil::unique_variant InterfaceMetric{};
	wil::unique_variant BaseReachableTime{};
	wil::unique_variant RetransmitTime{};
	wil::unique_variant DadTransmits{};
	wil::unique_variant RouterDiscovery{};
	wil::unique_variant ManagedAddressConfiguration{};
	wil::unique_variant OtherStatefulConfiguration{};
	wil::unique_variant WeakHostSend{};
	wil::unique_variant WeakHostReceive{};
	wil::unique_variant IgnoreDefaultRoutes{};
	wil::unique_variant AdvertisedRouterLifetime;
	wil::unique_variant AdvertiseDefaultRoute{};
	wil::unique_variant CurrentHopLimit{};
	wil::unique_variant ForceArpNdWolPattern{};
	wil::unique_variant DirectedMacWolPattern{};
	wil::unique_variant EcnMarking{};
	wil::unique_variant Dhcp{};
	wil::unique_variant AutomaticMetric{};
	wil::unique_variant DadRetransmitTime{};

	bool IsValid = false;
};
struct RecordedIpInterfaceProperties
{
	static constexpr auto IPv4AddressFamily = 0;
	static constexpr auto IPv6AddressFamily = 1;

	WritableIpInterfaceProperties ActiveStoreProperties[2];
	WritableIpInterfaceProperties PersistentStoreProperties[2];
};

inline RecordedIpInterfaceProperties ReadIPInterfaceProperties(uint32_t interfaceIndex)
{
	RecordedIpInterfaceProperties recordedProperties{};

	bool persistentStoreQuery = true;
	for (const auto& store : { L"PersistentStore", L"ActiveStore" })
	{
		wprintf(L"\n\nEnumerating NetIPInterface settings for interface index %u (%s)\n", interfaceIndex, store);
		const wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
		THROW_IF_FAILED(policyStoreContext->SetValue(
			L"PolicyStore",
			0,
			wil::make_variant_bstr(store).addressof()));

		const std::wstring query = L"SELECT * FROM MSFT_NetIPInterface WHERE InterfaceIndex = " + std::to_wstring(interfaceIndex);
		for (const auto& interface_instance : ctl::ctWmiEnumerateInstance::Query(query.c_str(), policyStoreContext))
		{
			// InterfaceIndex, AddressFamily, and Store are required properties
			WritableIpInterfaceProperties* properties = nullptr;

			uint32_t InterfaceIndexValue{};
			THROW_HR_IF(E_UNEXPECTED, !interface_instance.get(L"InterfaceIndex", &InterfaceIndexValue));
			if (InterfaceIndexValue != interfaceIndex)
			{
				std::printf("Unexpected InterfaceIndex value %u (expected %u)\n", InterfaceIndexValue, interfaceIndex);
				THROW_HR(E_UNEXPECTED);
			}

			uint8_t Store{}; // VT_UI1
			THROW_HR_IF(E_UNEXPECTED, !interface_instance.get(L"Store", &Store));
			if (persistentStoreQuery && Store != 0)
			{
				std::printf("Unexpected Store value %u for PersistentStore query (expected Store value of 0)\n", Store);
				THROW_HR(E_UNEXPECTED);
			}
			if (!persistentStoreQuery && Store != 1)
			{
				std::printf("Unexpected Store value %u for ActiveStore query (expected Store value of 1)\n", Store);
				THROW_HR(E_UNEXPECTED);
			}

			uint32_t AddressFamily{}; // VT_I4
			THROW_HR_IF(E_UNEXPECTED, !interface_instance.get(L"AddressFamily", &AddressFamily));
			if (AddressFamily == AF_INET)
			{
				properties = persistentStoreQuery ?
					&recordedProperties.PersistentStoreProperties[RecordedIpInterfaceProperties::IPv4AddressFamily] :
					&recordedProperties.ActiveStoreProperties[RecordedIpInterfaceProperties::IPv4AddressFamily];
			}
			else if (AddressFamily == AF_INET6)
			{
				properties = persistentStoreQuery ?
					&recordedProperties.PersistentStoreProperties[RecordedIpInterfaceProperties::IPv6AddressFamily] :
					&recordedProperties.ActiveStoreProperties[RecordedIpInterfaceProperties::IPv6AddressFamily];
			}
			else
			{
				std::printf("Unexpected AddressFamily value %u\n", AddressFamily);
				THROW_HR(E_UNEXPECTED);
			}

			properties->IsValid = true;
			interface_instance.get(L"Forwarding", &properties->Forwarding);
			interface_instance.get(L"ClampMss", &properties->ClampMss);
			interface_instance.get(L"Advertising", &properties->Advertising);
			interface_instance.get(L"NlMtu", &properties->NlMtu);
			interface_instance.get(L"InterfaceMetric", &properties->InterfaceMetric);
			interface_instance.get(L"BaseReachableTime", &properties->BaseReachableTime);
			interface_instance.get(L"RetransmitTime", &properties->RetransmitTime);
			interface_instance.get(L"DadTransmits", &properties->DadTransmits);
			interface_instance.get(L"RouterDiscovery", &properties->RouterDiscovery);
			interface_instance.get(L"ManagedAddressConfiguration", &properties->ManagedAddressConfiguration);
			interface_instance.get(L"OtherStatefulConfiguration", &properties->OtherStatefulConfiguration);
			interface_instance.get(L"WeakHostSend", &properties->WeakHostSend);
			interface_instance.get(L"WeakHostReceive", &properties->WeakHostReceive);
			interface_instance.get(L"IgnoreDefaultRoutes", &properties->IgnoreDefaultRoutes);
			interface_instance.get(L"AdvertisedRouterLifetime", &properties->AdvertisedRouterLifetime);
			interface_instance.get(L"AdvertiseDefaultRoute", &properties->AdvertiseDefaultRoute);
			interface_instance.get(L"CurrentHopLimit", &properties->CurrentHopLimit);
			interface_instance.get(L"ForceArpNdWolPattern", &properties->ForceArpNdWolPattern);
			interface_instance.get(L"DirectedMacWolPattern", &properties->DirectedMacWolPattern);
			interface_instance.get(L"EcnMarking", &properties->EcnMarking);
			interface_instance.get(L"Dhcp", &properties->Dhcp);
			interface_instance.get(L"AutomaticMetric", &properties->AutomaticMetric);
			interface_instance.get(L"DadRetransmitTime", &properties->DadRetransmitTime);

			wprintf(
				L"\n"
				L"  Interface Index: %d\n"
				L"  AddressFamily: %d\n"
				L"  Store: %d\n"
				L"  Forwarding: %ls\n"
				L"  ClampMss: %ls\n"
				L"  Advertising: %ls\n"
				L"  NlMtu: %ls\n"
				L"  InterfaceMetric: %ls\n"
				L"  BaseReachableTime: %ls\n"
				L"  RetransmitTime: %ls\n"
				L"  DadTransmits: %ls\n"
				L"  RouterDiscovery: %ls\n"
				L"  ManagedAddressConfiguration: %ls\n"
				L"  OtherStatefulConfiguration: %ls\n"
				L"  WeakHostSend: %ls\n"
				L"  WeakHostReceive: %ls\n"
				L"  IgnoreDefaultRoutes: %ls\n"
				L"  AdvertisedRouterLifetime: %ls\n"
				L"  AdvertiseDefaultRoute: %ls\n"
				L"  CurrentHopLimit: %ls\n"
				L"  ForceArpNdWolPattern: %ls\n"
				L"  DirectedMacWolPattern: %ls\n"
				L"  EcnMarking: %ls\n"
				L"  Dhcp: %ls\n"
				L"  AutomaticMetric: %ls\n"
				L"  DadRetransmitTime: %ls\n",
				InterfaceIndexValue,
				AddressFamily,
				Store,
				ctl::VariantToString(properties->Forwarding.addressof()).c_str(),
				ctl::VariantToString(properties->ClampMss.addressof()).c_str(),
				ctl::VariantToString(properties->Advertising.addressof()).c_str(),
				ctl::VariantToString(properties->NlMtu.addressof()).c_str(),
				ctl::VariantToString(properties->InterfaceMetric.addressof()).c_str(),
				ctl::VariantToString(properties->BaseReachableTime.addressof()).c_str(),
				ctl::VariantToString(properties->RetransmitTime.addressof()).c_str(),
				ctl::VariantToString(properties->DadTransmits.addressof()).c_str(),
				ctl::VariantToString(properties->RouterDiscovery.addressof()).c_str(),
				ctl::VariantToString(properties->ManagedAddressConfiguration.addressof()).c_str(),
				ctl::VariantToString(properties->OtherStatefulConfiguration.addressof()).c_str(),
				ctl::VariantToString(properties->WeakHostSend.addressof()).c_str(),
				ctl::VariantToString(properties->WeakHostReceive.addressof()).c_str(),
				ctl::VariantToString(properties->IgnoreDefaultRoutes.addressof()).c_str(),
				ctl::VariantToString(properties->AdvertisedRouterLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->AdvertiseDefaultRoute.addressof()).c_str(),
				ctl::VariantToString(properties->CurrentHopLimit.addressof()).c_str(),
				ctl::VariantToString(properties->ForceArpNdWolPattern.addressof()).c_str(),
				ctl::VariantToString(properties->DirectedMacWolPattern.addressof()).c_str(),
				ctl::VariantToString(properties->EcnMarking.addressof()).c_str(),
				ctl::VariantToString(properties->Dhcp.addressof()).c_str(),
				ctl::VariantToString(properties->AutomaticMetric.addressof()).c_str(),
				ctl::VariantToString(properties->DadRetransmitTime.addressof()).c_str());
		}

		// 2nd pass is for ActiveStore
		persistentStoreQuery = false;
	}

	return recordedProperties;
}

inline HRESULT WriteIPInterfaceProperties(const RecordedIpInterfaceProperties& recordedProperties, uint32_t interface_index)
try
{
	// for demonstration purposes, we'll just write the same properties back to the interface
	// in a real-world scenario, you would likely modify some of these properties before writing them back

	bool persistentStoreQuery = true;
	for (const auto& store : { L"PersistentStore", L"ActiveStore" })
	{
		wprintf(L"\n\nEnumerating NetIPInterface objects for the target interface %u (%s)\n", interface_index, store);
		const wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
		THROW_IF_FAILED(policyStoreContext->SetValue(
			L"PolicyStore",
			0,
			wil::make_variant_bstr(store).addressof()));

		const std::wstring query = L"SELECT * FROM MSFT_NetIPInterface WHERE InterfaceIndex = " + std::to_wstring(interface_index);
		for (auto& interface_instance : ctl::ctWmiEnumerateInstance::Query(query.c_str(), policyStoreContext))
		{
			// InterfaceIndex, AddressFamily, and Store are required properties
			const WritableIpInterfaceProperties* properties = nullptr;

			uint32_t InterfaceIndexValue{};
			THROW_HR_IF(E_UNEXPECTED, !interface_instance.get(L"InterfaceIndex", &InterfaceIndexValue));
			if (InterfaceIndexValue != interface_index)
			{
				std::printf("Unexpected InterfaceIndex value %u (expected %u)\n", InterfaceIndexValue, interface_index);
				THROW_HR(E_UNEXPECTED);
			}

			uint8_t Store{}; // VT_UI1
			THROW_HR_IF(E_UNEXPECTED, !interface_instance.get(L"Store", &Store));
			if (persistentStoreQuery && Store != 0)
			{
				std::printf("Unexpected Store value %u for PersistentStore query (expected Store value of 0)\n", Store);
				THROW_HR(E_UNEXPECTED);
			}
			if (!persistentStoreQuery && Store != 1)
			{
				std::printf("Unexpected Store value %u for ActiveStore query (expected Store value of 1)\n", Store);
				THROW_HR(E_UNEXPECTED);
			}

			uint32_t AddressFamily{}; // VT_I4
			THROW_HR_IF(E_UNEXPECTED, !interface_instance.get(L"AddressFamily", &AddressFamily));
			if (AddressFamily == AF_INET)
			{
				properties = persistentStoreQuery ?
					&recordedProperties.PersistentStoreProperties[RecordedIpInterfaceProperties::IPv4AddressFamily] :
					&recordedProperties.ActiveStoreProperties[RecordedIpInterfaceProperties::IPv4AddressFamily];
			}
			else if (AddressFamily == AF_INET6)
			{
				properties = persistentStoreQuery ?
					&recordedProperties.PersistentStoreProperties[RecordedIpInterfaceProperties::IPv6AddressFamily] :
					&recordedProperties.ActiveStoreProperties[RecordedIpInterfaceProperties::IPv6AddressFamily];
			}
			else
			{
				std::printf("Unexpected AddressFamily value %u\n", AddressFamily);
				THROW_HR(E_UNEXPECTED);
			}

			if (!properties->IsValid)
			{
				std::printf("No recorded properties for AddressFamily %u in %ls\n", AddressFamily, store);
				continue;
			}

			const auto LogFailure = [&](PCWSTR propertyName, HRESULT hr)  noexcept {
				std::printf(" - Failed to set %ls property for AddressFamily %u in %ls (0x%08X)\n", propertyName, AddressFamily, store, hr);
				};

			HRESULT hrAggregate = S_OK;
			HRESULT hr{};
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"Forwarding", properties->Forwarding)))
			{
				hrAggregate = hr;
				LogFailure(L"Forwarding", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"ClampMss", properties->ClampMss)))
			{
				hrAggregate = hr;
				LogFailure(L"ClampMss", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"Advertising", properties->Advertising)))
			{
				hrAggregate = hr;
				LogFailure(L"Advertising", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"NlMtu", properties->NlMtu)))
			{
				hrAggregate = hr;
				LogFailure(L"NlMtu", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"InterfaceMetric", properties->InterfaceMetric)))
			{
				hrAggregate = hr;
				LogFailure(L"InterfaceMetric", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"BaseReachableTime", properties->BaseReachableTime)))
			{
				hrAggregate = hr;
				LogFailure(L"BaseReachableTime", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"RetransmitTime", properties->RetransmitTime)))
			{
				hrAggregate = hr;
				LogFailure(L"RetransmitTime", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"DadTransmits", properties->DadTransmits)))
			{
				hrAggregate = hr;
				LogFailure(L"DadTransmits", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"RouterDiscovery", properties->RouterDiscovery)))
			{
				hrAggregate = hr;
				LogFailure(L"RouterDiscovery", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"ManagedAddressConfiguration", properties->ManagedAddressConfiguration)))
			{
				hrAggregate = hr;
				LogFailure(L"ManagedAddressConfiguration", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"OtherStatefulConfiguration", properties->OtherStatefulConfiguration)))
			{
				hrAggregate = hr;
				LogFailure(L"OtherStatefulConfiguration", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"WeakHostSend", properties->WeakHostSend)))
			{
				hrAggregate = hr;
				LogFailure(L"WeakHostSend", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"WeakHostReceive", properties->WeakHostReceive)))
			{
				hrAggregate = hr;
				LogFailure(L"WeakHostReceive", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"IgnoreDefaultRoutes", properties->IgnoreDefaultRoutes)))
			{
				hrAggregate = hr;
				LogFailure(L"IgnoreDefaultRoutes", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"AdvertisedRouterLifetime", properties->AdvertisedRouterLifetime)))
			{
				hrAggregate = hr;
				LogFailure(L"AdvertisedRouterLifetime", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"AdvertiseDefaultRoute", properties->AdvertiseDefaultRoute)))
			{
				hrAggregate = hr;
				LogFailure(L"AdvertiseDefaultRoute", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"CurrentHopLimit", properties->CurrentHopLimit)))
			{
				hrAggregate = hr;
				LogFailure(L"CurrentHopLimit", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"ForceArpNdWolPattern", properties->ForceArpNdWolPattern)))
			{
				hrAggregate = hr;
				LogFailure(L"ForceArpNdWolPattern", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"DirectedMacWolPattern", properties->DirectedMacWolPattern)))
			{
				hrAggregate = hr;
				LogFailure(L"DirectedMacWolPattern", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"EcnMarking", properties->EcnMarking)))
			{
				hrAggregate = hr;
				LogFailure(L"EcnMarking", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"Dhcp", properties->Dhcp)))
			{
				hrAggregate = hr;
				LogFailure(L"Dhcp", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"AutomaticMetric", properties->AutomaticMetric)))
			{
				hrAggregate = hr;
				LogFailure(L"AutomaticMetric", hr);
			}
			if (FAILED(hr = interface_instance.set_if_not_null_no_throw(L"DadRetransmitTime", properties->DadRetransmitTime)))
			{
				hrAggregate = hr;
				LogFailure(L"DadRetransmitTime", hr);
			}

			hr = interface_instance.write_instance_no_throw(policyStoreContext.get());
			std::printf("Attempting to update all properties for AddressFamily %u in %ls %ls -- writing the instance returned 0x%08lX\n",
				AddressFamily,
				store,
				FAILED(hrAggregate) ? L"failed" : L"succeeded",
				hr);
		}

		// 2nd pass is for ActiveStore
		persistentStoreQuery = false;
	}

	return S_OK;
}
CATCH_RETURN()