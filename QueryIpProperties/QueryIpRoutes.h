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
	class MSFT_NetRoute : CIM_NextHopRoute
	{
		[read: ToSubClass] string DestinationPrefix;
		[read: ToSubClass] uint32 InterfaceIndex;
		[read: ToSubClass] string InterfaceAlias;
		[read: ToSubClass] string NextHop;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1", "2"}: ToSubClass] uint8 Publish;
		[read: ToSubClass, write: ToSubClass] datetime ValidLifetime;
		[read: ToSubClass, write: ToSubClass] datetime PreferredLifetime;
		[ValueMap{"0", "1"}: ToSubClass, read: ToSubClass] uint8 Store;
		[read: ToSubClass, ValueMap{"2", "23"}: ToSubClass] uint16 AddressFamily;
		[read: ToSubClass, ValueMap{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19"}: ToSubClass] uint16 Protocol;
		[read: ToSubClass] uint32 CompartmentId;
		[read: ToSubClass, ValueMap{"0", "1", "2"}: ToSubClass] uint8 State;
		[read: ToSubClass] uint32 InterfaceMetric;
		[implemented, static: DisableOverride ToSubClass] uint32 Create([In] uint32 InterfaceIndex, [In] string InterfaceAlias, [In] string DestinationPrefix, [In] string NextHop, [In] uint8 Publish, [In] uint16 RouteMetric, [In] uint16 Protocol, [In] uint32 CompartmentId, [In] datetime ValidLifetime, [In] datetime PreferredLifetime, [In] string PolicyStore, [In] uint16 AddressFamily, [In] boolean PassThru, [Out, EmbeddedInstance("MSFT_NetRoute"): ToSubClass] MSFT_NetRoute CmdletOutput[]);
		[implemented, static: DisableOverride ToSubClass] uint32 Find([In] uint32 InterfaceIndex, [In] string LocalIPAddress, [In] string RemoteIPAddress, [Out, EmbeddedInstance("CIM_ManagedElement"): ToSubClass] CIM_ManagedElement CmdletOutput[]);
	};
	class CIM_NextHopRoute : CIM_ManagedElement
	{
		[key, Override("InstanceID")] string InstanceID = NULL;
	//// DestinationAddress is not set by MSFT_NetRoute
		string DestinationAddress;
	//// AdminDistance is not set by MSFT_NetRoute
		uint16 AdminDistance;
	//// RouteMetric **is** set by MSFT_NetRoute
		uint16 RouteMetric;
	//// IsStatic is not set by MSFT_NetRoute
		boolean IsStatic;
	//// TypeOfRoute **is** set by MSFT_NetRoute
		[ValueMap{"2", "3", "4"}: ToSubClass] uint16 TypeOfRoute = 3;
	};
 */

struct RouteProperties
{
	wil::unique_variant DestinationPrefix{};
	wil::unique_variant NextHop{};
	wil::unique_variant Publish{};
	wil::unique_variant ValidLifetime{};
	wil::unique_variant PreferredLifetime{};
	wil::unique_variant Protocol{};
	wil::unique_variant CompartmentId{};
	wil::unique_variant RouteMetric{};
};

struct RecordedRouteProperties
{
	uint32_t InterfaceIndex{};
	wil::unique_variant InterfaceAlias{};

	RouteProperties ActiveStoreProperties;
	RouteProperties PersistentStoreProperties;
};

static std::vector<RecordedRouteProperties> QueryIPRouteProperties(uint32_t interfaceIndex)
{
	std::vector<RecordedRouteProperties> allRecordedProperties{};

	bool persistentStoreQuery = true;
	for (const auto& store : { L"PersistentStore", L"ActiveStore" })
	{
		wprintf(L"\n\nEnumerating NetRoute settings for interface index %u (%s)\n", interfaceIndex, store);
		const wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
		THROW_IF_FAILED(policyStoreContext->SetValue(
			L"PolicyStore",
			0,
			wil::make_variant_bstr(store).addressof()));

		// Protocol = 3 filters for routes with Protocol value of 3 ("NetMgmt").
		// This is done to filter for routes that are created by the system/OS.
		const std::wstring query = L"SELECT * FROM MSFT_NetRoute WHERE InterfaceIndex = " + std::to_wstring(interfaceIndex) + L" AND Protocol = 3"; 
		std::wprintf(L"Querying WMI with: %ls\n", query.c_str());
		for (const auto& route_instance : ctl::ctWmiEnumerateInstance::Query(query.c_str(), policyStoreContext))
		{
			uint8_t Store{};
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"Store", &Store));
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

			allRecordedProperties.push_back(RecordedRouteProperties{});
			RecordedRouteProperties& recordedProperties = allRecordedProperties.back();
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"InterfaceIndex", &recordedProperties.InterfaceIndex));
			if (recordedProperties.InterfaceIndex != interfaceIndex)
			{
				std::printf("Unexpected InterfaceIndex value %u (expected %u)\n", recordedProperties.InterfaceIndex, interfaceIndex);
				THROW_HR(E_UNEXPECTED);
			}
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"InterfaceAlias", &recordedProperties.InterfaceAlias));

			RouteProperties* properties = persistentStoreQuery ?
				&recordedProperties.PersistentStoreProperties :
				&recordedProperties.ActiveStoreProperties;

			route_instance.get(L"DestinationPrefix", &properties->DestinationPrefix);
			route_instance.get(L"NextHop", &properties->NextHop);
			route_instance.get(L"Publish", &properties->Publish);
			route_instance.get(L"ValidLifetime", &properties->ValidLifetime);
			route_instance.get(L"PreferredLifetime", &properties->PreferredLifetime);
			route_instance.get(L"Protocol", &properties->Protocol);
			route_instance.get(L"CompartmentId", &properties->CompartmentId);
			route_instance.get(L"RouteMetric", &properties->RouteMetric);
			/*
			wprintf(
				L"\n"
				L"  Store: %d\n"
				L"  Interface Index: %d\n"
				L"  Interface Alias: %ls\n"
				L"  DestinationPrefix: %ls\n"
				L"  NextHop: %ls\n"
				L"  Publish: %ls\n"
				L"  ValidLifetime: %ls\n"
				L"  PreferredLifetime: %ls\n"
				L"  Protocol: %ls\n"
				L"  RouteMetric: %ls\n",
				Store,
				recordedProperties.InterfaceIndex,
				ctl::VariantToString(recordedProperties.InterfaceAlias.addressof()).c_str(),
				ctl::VariantToString(properties->DestinationPrefix.addressof()).c_str(),
				ctl::VariantToString(properties->NextHop.addressof()).c_str(),
				ctl::VariantToString(properties->Publish.addressof()).c_str(),
				ctl::VariantToString(properties->ValidLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->PreferredLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->Protocol.addressof()).c_str(),
				ctl::VariantToString(properties->RouteMetric.addressof()).c_str());
				*/
		}

		persistentStoreQuery = false;
	}

	std::printf("\n * Found %d matching routes\n", static_cast<int>(allRecordedProperties.size()));
	return allRecordedProperties;
}
