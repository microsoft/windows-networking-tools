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
	class MSFT_NetIPAddress : CIM_IPProtocolEndpoint
	{
		[read: ToSubClass] uint32 InterfaceIndex;
		[read: ToSubClass] string InterfaceAlias;
		[read: ToSubClass] string IPAddress;
		[read: ToSubClass, ValueMap{"2", "23"}: ToSubClass] uint16 AddressFamily;
		[ValueMap{"1", "2"}: ToSubClass, read: ToSubClass] uint8 Type;
		[ValueMap{"0", "1"}: ToSubClass, read: ToSubClass] uint8 Store;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1", "2", "3", "4"}: ToSubClass] uint16 PrefixOrigin;
		[read: ToSubClass, write: ToSubClass, ValueMap{"0", "1", "2", "3", "4", "5"}: ToSubClass] uint16 SuffixOrigin;
		[read: ToSubClass, ValueMap{"0", "1", "2", "3", "4"}: ToSubClass] uint16 AddressState;
		[read: ToSubClass, write: ToSubClass] datetime ValidLifetime;
		[read: ToSubClass, write: ToSubClass] datetime PreferredLifetime;
		[read: ToSubClass, write: ToSubClass] boolean SkipAsSource;
		[implemented, static: DisableOverride ToSubClass] uint32 Create([In] uint32 InterfaceIndex, [In] string InterfaceAlias, [In] string IPAddress, [In] uint16 AddressFamily, [In] uint8 PrefixLength, [In] uint8 Type, [In] uint16 PrefixOrigin, [In] uint16 SuffixOrigin, [In] uint16 AddressState, [In] datetime ValidLifetime, [In] datetime PreferredLifetime, [In] boolean SkipAsSource, [In] string DefaultGateway, [In] string PolicyStore, [In] boolean PassThru, [Out, EmbeddedInstance("MSFT_NetIPAddress"): ToSubClass] MSFT_NetIPAddress CmdletOutput[]);
	};
	class CIM_IPProtocolEndpoint : CIM_ProtocolEndpoint
	{
		[ValueMap{"1", "225..4095", "4096", "4097", "4098", "4301..32767", "32768.."}: ToSubClass, ModelCorrespondence{"CIM_ProtocolEndpoint.OtherTypeDescription"}: ToSubClass, Override("ProtocolIFType")] uint16 ProtocolIFType = 4096;
	//// IPv4Address **or** IPv6Address **is** set by MSFT_NetIPAddress
		string IPv4Address;
		string IPv6Address;
		[Deprecated{"CIM_IPProtocolEndpoint.IPv4Address", "CIM_IPProtocolEndpoint.IPv6Address"}] string Address;
		string SubnetMask;
	//// PrefixLength **is** set by MSFT_NetIPAddress
		uint8 PrefixLength;
		[Deprecated{"No value"}, ValueMap{"0", "1", "2"}: ToSubClass] uint16 AddressType;
		[Deprecated{"CIM_ProtocolEndpoint.ProtocolIFType"}, ValueMap{"0", "1", "2", "3"}: ToSubClass] uint16 IPVersionSupport;
		[ValueMap{"0", "1", "2", "3", "4", "5", "6", "7", "8", "..", "32768..65535"}: ToSubClass] uint16 AddressOrigin = 0;
	};
 */

struct WritableAddressProperties
{
	wil::unique_variant AddressFamily{};
	wil::unique_variant IPAddress{};
	wil::unique_variant PrefixOrigin{};
	wil::unique_variant SuffixOrigin{};
	wil::unique_variant ValidLifetime{};
	wil::unique_variant PreferredLifetime{};
	wil::unique_variant SkipAsSource{};
	wil::unique_variant PrefixLength{};
};

struct RecordedAddressProperties
{
	uint32_t InterfaceIndex{};
	std::wstring InterfaceAlias{};

	WritableAddressProperties ActiveStoreProperties;
	WritableAddressProperties PersistentStoreProperties;
};

static std::vector<RecordedAddressProperties> MigrateIPAddressProperties(uint32_t interfaceIndex)
{
	std::vector<RecordedAddressProperties> allRecordedProperties{};

	bool persistentStoreQuery = true;
	for (const auto& store : { L"PersistentStore", L"ActiveStore" })
	{
		wprintf(L"\n\nEnumerating NetIPAddress settings for interface index %u (%s)\n", interfaceIndex, store);
		const wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
		THROW_IF_FAILED(policyStoreContext->SetValue(
			L"PolicyStore",
			0,
			wil::make_variant_bstr(store).addressof()));

		// filters for addresses that are statically assigned (i.e. not from DHCP, SLAAC, etc.)
		const std::wstring query = L"SELECT * FROM MSFT_NetIPAddress WHERE InterfaceIndex = " + std::to_wstring(interfaceIndex) + L" AND PrefixOrigin = 1 AND SuffixOrigin = 1";
		std::wprintf(L"Querying WMI with: %ls\n", query.c_str());
		for (const auto& address_instance : ctl::ctWmiEnumerateInstance::Query(query.c_str(), policyStoreContext))
		{
			uint8_t Store{};
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"Store", &Store));
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

			allRecordedProperties.push_back(RecordedAddressProperties{});
			RecordedAddressProperties& recordedProperties = allRecordedProperties.back();

			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"InterfaceIndex", &recordedProperties.InterfaceIndex));
			if (recordedProperties.InterfaceIndex != interfaceIndex)
			{
				std::printf("Unexpected InterfaceIndex value %u (expected %u)\n", recordedProperties.InterfaceIndex, interfaceIndex);
				THROW_HR(E_UNEXPECTED);
			}
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"InterfaceAlias", &recordedProperties.InterfaceAlias));

			WritableAddressProperties* properties = persistentStoreQuery ?
				&recordedProperties.PersistentStoreProperties :
				&recordedProperties.ActiveStoreProperties;

			address_instance.get(L"AddressFamily", &properties->AddressFamily);
			address_instance.get(L"IPAddress", &properties->IPAddress);
			address_instance.get(L"PrefixOrigin", &properties->PrefixOrigin);
			address_instance.get(L"SuffixOrigin", &properties->SuffixOrigin);
			address_instance.get(L"ValidLifetime", &properties->ValidLifetime);
			address_instance.get(L"PreferredLifetime", &properties->PreferredLifetime);
			address_instance.get(L"SkipAsSource", &properties->SkipAsSource);
			address_instance.get(L"PrefixLength", &properties->PrefixLength);

			wprintf(
				L"\n"
				L"  Store: %d\n"
				L"  Interface Index: %d\n"
				L"  Interface Alias: %ls\n"
				L"  IPAddress: %ls\n"
				L"  AddressFamily: %ls\n"
				L"  PrefixOrigin: %ls\n"
				L"  SuffixOrigin: %ls\n"
				L"  ValidLifetime: %ls\n"
				L"  PreferredLifetime: %ls\n"
				L"  SkipAsSource: %ls\n"
				L"  PrefixLength: %ls\n",
				Store,
				recordedProperties.InterfaceIndex,
				recordedProperties.InterfaceAlias.c_str(),
				ctl::VariantToString(properties->IPAddress).c_str(),
				ctl::VariantToString(properties->AddressFamily).c_str(),
				ctl::VariantToString(properties->PrefixOrigin.addressof()).c_str(),
				ctl::VariantToString(properties->SuffixOrigin.addressof()).c_str(),
				ctl::VariantToString(properties->ValidLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->PreferredLifetime.addressof()).c_str(),
				ctl::VariantToString(properties->SkipAsSource.addressof()).c_str(),
				ctl::VariantToString(properties->PrefixLength.addressof()).c_str());
		}

		persistentStoreQuery = false;
	}

	std::printf("\n * Found %d matching addresses\n", static_cast<int>(allRecordedProperties.size()));
	return allRecordedProperties;
}
