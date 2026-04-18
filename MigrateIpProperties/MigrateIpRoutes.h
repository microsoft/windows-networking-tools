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
	wil::unique_variant AddressFamily{};
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
	uint8_t Store{};
	uint32_t InterfaceIndex{};
	wil::unique_variant InterfaceAlias{};
	RouteProperties properties{};
};

inline std::vector<RecordedRouteProperties> ReadIPRoutes(uint32_t interfaceIndex)
{
	std::vector<RecordedRouteProperties> saved_routes{};

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
			saved_routes.push_back(RecordedRouteProperties{});
			RecordedRouteProperties& route_properties = saved_routes.back();
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"InterfaceIndex", &route_properties.InterfaceIndex));
			if (route_properties.InterfaceIndex != interfaceIndex)
			{
				std::printf("Unexpected InterfaceIndex value %u (expected %u)\n", route_properties.InterfaceIndex, interfaceIndex);
				THROW_HR(E_UNEXPECTED);
			}
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"InterfaceAlias", &route_properties.InterfaceAlias));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"Store", &route_properties.Store));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"AddressFamily", &route_properties.properties.AddressFamily));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"DestinationPrefix", &route_properties.properties.DestinationPrefix));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"NextHop", &route_properties.properties.NextHop));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"Publish", &route_properties.properties.Publish));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"ValidLifetime", &route_properties.properties.ValidLifetime));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"PreferredLifetime", &route_properties.properties.PreferredLifetime));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"Protocol", &route_properties.properties.Protocol));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"CompartmentId", &route_properties.properties.CompartmentId));
			THROW_HR_IF(E_UNEXPECTED, !route_instance.get(L"RouteMetric", &route_properties.properties.RouteMetric));
			/*
			wprintf(
				L"\n"
				L"  Store: %d\n"
				L"  Interface Index: %d\n"
				L"  Interface Alias: %ls\n"
				L"  AddressFamily: %ls\n"
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
				ctl::VariantToString(properties->AddressFamily.addressof()).c_str(),
				ctl::VariantToString(properties->DestinationPrefix.addressof()).c_str(),
				ctl::VariantToString(properties->NextHop.addressof()).c_str(),
				ctl::VariantToString(properties->Publish.addressof()).c_str(),
				ctl::VariantToString(properties->ValidLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->PreferredLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->Protocol.addressof()).c_str(),
				ctl::VariantToString(properties->RouteMetric.addressof()).c_str());
			*/
		}
	}

	std::printf("\n * Found %d network-management-marked routes (Protocol == NetMgmt)\n", static_cast<int>(saved_routes.size()));
	return saved_routes;
}

inline void WriteIPRoutes(std::vector<RecordedRouteProperties> originalProperties, uint32_t interfaceIndex)
{
	ctl::ctWmiService wmiService(L"ROOT\\StandardCimv2"); // MSFT_NetRoute is in ROOT\StandardCimv2 namespace

	for (auto& original_route : originalProperties)
	{
		// [implemented, static: DisableOverride ToSubClass] uint32 Create(
		//	[In] uint32 InterfaceIndex,
		//	[In] string InterfaceAlias,
		//	[In] string DestinationPrefix,
		//	[In] string NextHop,
		//	[In] uint8 Publish,
		//	[In] uint16 RouteMetric,
		//	[In] uint16 Protocol,
		//	[In] uint32 CompartmentId,
		//	[In] datetime ValidLifetime,
		//	[In] datetime PreferredLifetime,
		//	[In] string PolicyStore,
		//	[In] uint16 AddressFamily,
		//	[In] boolean PassThru,
		//	[Out, EmbeddedInstance("MSFT_NetRoute"): ToSubClass] MSFT_NetRoute CmdletOutput[]);

		ctl::ctWmiStaticMethod create_route(L"MSFT_NetRoute", L"Create", wmiService);
		create_route.add_parameter(L"InterfaceIndex", ctl::ctWmiMakeVariant(interfaceIndex).addressof());
		create_route.add_parameter(L"InterfaceAlias", nullptr);
		create_route.add_parameter(L"AddressFamily", original_route.properties.AddressFamily.addressof());
		create_route.add_parameter(L"DestinationPrefix", original_route.properties.DestinationPrefix.addressof());
		create_route.add_parameter(L"NextHop", original_route.properties.NextHop.addressof());
		create_route.add_parameter(L"Publish", original_route.properties.Publish.addressof());
		create_route.add_parameter(L"RouteMetric", original_route.properties.RouteMetric.addressof());
		create_route.add_parameter(L"Protocol", original_route.properties.Protocol.addressof());
		create_route.add_parameter(L"CompartmentId", original_route.properties.CompartmentId.addressof());
		create_route.add_parameter(L"ValidLifetime", original_route.properties.ValidLifetime.addressof());
		create_route.add_parameter(L"PreferredLifetime", original_route.properties.PreferredLifetime.addressof());
		create_route.add_parameter(L"PolicyStore", original_route.Store == 0 ? nullptr : ctl::ctWmiMakeVariant(L"ActiveStore").addressof());
		create_route.add_parameter(L"PassThru", ctl::ctWmiMakeVariant(false).addressof());
		const auto hr = create_route.execute_method_nothrow();

		// print the result of the execute_method call, but continue with the next route even if it failed
		if (SUCCEEDED(hr))
		{
			std::wprintf(L"Successfully created route with DestinationPrefix %ls and NextHop %ls\n",
				ctl::VariantToString(original_route.properties.DestinationPrefix.addressof()).c_str(),
				ctl::VariantToString(original_route.properties.NextHop.addressof()).c_str());
		}
		else
		{
			std::wprintf(L"Failed to create route with DestinationPrefix %ls and NextHop %ls. HRESULT: 0x%08X\n",
				ctl::VariantToString(original_route.properties.DestinationPrefix.addressof()).c_str(),
				ctl::VariantToString(original_route.properties.NextHop.addressof()).c_str(),
				hr);
		}
	}
}
