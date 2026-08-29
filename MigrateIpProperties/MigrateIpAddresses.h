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
	wil::unique_variant AddressState{};
	wil::unique_variant ValidLifetime{};
	wil::unique_variant PreferredLifetime{};
	wil::unique_variant SkipAsSource{};
	wil::unique_variant PrefixLength{};
};

struct RecordedAddressProperties
{
	uint8_t Store{};
	std::wstring InterfaceAlias{};
	WritableAddressProperties properties{};
};

inline std::vector<RecordedAddressProperties> ReadIPAddresses(uint32_t interfaceIndex)
{
	std::vector<RecordedAddressProperties> saved_addresses{};

	for (const auto& store : { L"PersistentStore", L"ActiveStore" })
	{
		wprintf(L"\n\nEnumerating NetIPAddress settings for interface index %u (%s)\n", interfaceIndex, store);
		const wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
		THROW_IF_FAILED(policyStoreContext->SetValue(
			L"PolicyStore",
			0,
			wil::make_variant_bstr(store).addressof()));

		// filters for addresses that are statically assigned (i.e. not from DHCP, SLAAC, etc.)
		// only querying for unicast addresses (Type = 1)
		const std::wstring query = L"SELECT * FROM MSFT_NetIPAddress WHERE InterfaceIndex = " + std::to_wstring(interfaceIndex) + L" AND Type = 1 AND PrefixOrigin = 1 AND SuffixOrigin = 1";
		std::wprintf(L"Querying WMI with: %ls\n", query.c_str());
		for (auto& address_instance : ctl::ctWmiEnumerateInstance::Query(query.c_str(), policyStoreContext))
		{
			uint32_t queried_interface_index{};
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"InterfaceIndex", &queried_interface_index));
			if (queried_interface_index != interfaceIndex)
			{
				std::printf("Unexpected InterfaceIndex value %u (expected %u)\n", queried_interface_index, interfaceIndex);
				THROW_HR(E_UNEXPECTED);
			}

			saved_addresses.push_back(RecordedAddressProperties{});
			RecordedAddressProperties& address_properties = saved_addresses.back();

			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"InterfaceAlias", &address_properties.InterfaceAlias));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"Store", &address_properties.Store));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"AddressFamily", &address_properties.properties.AddressFamily));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"IPAddress", &address_properties.properties.IPAddress));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"PrefixOrigin", &address_properties.properties.PrefixOrigin));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"SuffixOrigin", &address_properties.properties.SuffixOrigin));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"AddressState", &address_properties.properties.AddressState));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"ValidLifetime", &address_properties.properties.ValidLifetime));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"PreferredLifetime", &address_properties.properties.PreferredLifetime));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"SkipAsSource", &address_properties.properties.SkipAsSource));
			THROW_HR_IF(E_UNEXPECTED, !address_instance.get(L"PrefixLength", &address_properties.properties.PrefixLength));

			wprintf(
				L"\n"
				L"  Store: %d\n"
				L"  Interface Index: %d\n"
				L"  Interface Alias: %ls\n"
				L"  IPAddress: %ls\n"
				L"  AddressFamily: %ls\n"
				L"  PrefixOrigin: %ls\n"
				L"  SuffixOrigin: %ls\n"
				L"  AddressState: %ls\n"
				L"  ValidLifetime: %ls\n"
				L"  PreferredLifetime: %ls\n"
				L"  SkipAsSource: %ls\n"
				L"  PrefixLength: %ls\n",
				address_properties.Store,
				interfaceIndex,
				address_properties.InterfaceAlias.c_str(),
				ctl::VariantToString(address_properties.properties.IPAddress).c_str(),
				ctl::VariantToString(address_properties.properties.AddressFamily).c_str(),
				ctl::VariantToString(address_properties.properties.PrefixOrigin.addressof()).c_str(),
				ctl::VariantToString(address_properties.properties.SuffixOrigin.addressof()).c_str(),
				ctl::VariantToString(address_properties.properties.AddressState.addressof()).c_str(),
				ctl::VariantToString(address_properties.properties.ValidLifetime.addressof()).c_str(),
				ctl::VariantToString(address_properties.properties.PreferredLifetime.addressof()).c_str(),
				ctl::VariantToString(address_properties.properties.SkipAsSource.addressof()).c_str(),
				ctl::VariantToString(address_properties.properties.PrefixLength.addressof()).c_str());

			const auto delete_hr = address_instance.delete_instance_no_throw();
			wprintf(L"  Deleting original address instance... %s (0x%x)\n", SUCCEEDED(delete_hr) ? L"Succeeded" : L"Failed", delete_hr);
		}
	}

	std::printf("\n * Found %d matching addresses\n", static_cast<int>(saved_addresses.size()));
	return saved_addresses;
}

inline void WriteIPAddresses(std::vector<RecordedAddressProperties>&& originalProperties, uint32_t interfaceIndex)
{
	ctl::ctWmiService wmiService(L"ROOT\\StandardCimv2"); // MSFT_NetRoute is in ROOT\StandardCimv2 namespace

	for (auto& original_address : originalProperties)
	{
		// [implemented, static: DisableOverride ToSubClass] uint32 Create(
		//  [In] uint32 InterfaceIndex,
		//  [In] string InterfaceAlias,
		//  [In] string IPAddress,
		//  [In] uint16 AddressFamily,
		//  [In] uint8 PrefixLength,
		//  [In] uint8 Type,
		//  [In] uint16 PrefixOrigin,
		//  [In] uint16 SuffixOrigin,
		//  [In] uint16 AddressState,
		//  [In] datetime ValidLifetime,
		//  [In] datetime PreferredLifetime,
		//  [In] boolean SkipAsSource,
		//  [In] string DefaultGateway,
		//  [In] string PolicyStore,
		//  [In] boolean PassThru,
		//  [Out, EmbeddedInstance("MSFT_NetIPAddress"): ToSubClass] MSFT_NetIPAddress CmdletOutput[]);

		ctl::ctWmiStaticMethod create_address(L"MSFT_NetIPAddress", L"Create", wmiService);
		create_address.add_parameter(L"InterfaceIndex", ctl::ctWmiMakeVariant(interfaceIndex).addressof());
		create_address.add_parameter(L"InterfaceAlias", nullptr);
		create_address.add_parameter(L"IPAddress", original_address.properties.IPAddress.addressof());
		create_address.add_parameter(L"AddressFamily", original_address.properties.AddressFamily.addressof());
		create_address.add_parameter(L"PrefixLength", original_address.properties.PrefixLength.addressof());
		create_address.add_parameter(L"Type", ctl::ctWmiMakeVariant(1).addressof());
		create_address.add_parameter(L"PrefixOrigin", original_address.properties.PrefixOrigin.addressof());
		create_address.add_parameter(L"SuffixOrigin", original_address.properties.SuffixOrigin.addressof());
		create_address.add_parameter(L"AddressState", original_address.properties.AddressState.addressof());
		create_address.add_parameter(L"ValidLifetime", original_address.properties.ValidLifetime.addressof());
		create_address.add_parameter(L"PreferredLifetime", original_address.properties.PreferredLifetime.addressof());
		create_address.add_parameter(L"SkipAsSource", original_address.properties.SkipAsSource.addressof());
		create_address.add_parameter(L"DefaultGateway", nullptr);
		create_address.add_parameter(L"PolicyStore", original_address.Store == 0 ? nullptr : ctl::ctWmiMakeVariant(L"ActiveStore").addressof());
		create_address.add_parameter(L"PassThru", ctl::ctWmiMakeVariant(false).addressof());
		const auto hr = create_address.execute_method_nothrow();

		// print the result of the execute_method call, but continue with the next route even if it failed
		if (SUCCEEDED(hr))
		{
			std::wprintf(L"Successfully created address (%ls) from Store %u with PrefixLength %ls\n",
				ctl::VariantToString(original_address.properties.IPAddress.addressof()).c_str(),
				original_address.Store,
				ctl::VariantToString(original_address.properties.PrefixLength.addressof()).c_str());
		}
		else
		{
			std::wprintf(L"Failed to create address (%ls) from Store %u with PrefixLength %ls (0x%x)\n",
				ctl::VariantToString(original_address.properties.IPAddress.addressof()).c_str(),
				original_address.Store,
				ctl::VariantToString(original_address.properties.PrefixLength.addressof()).c_str(),
				hr);
		}
	}
}

/*
        ctWmiInstance instance(this->wmiService, L"MSFT_NetIPAddress");
        instance.set(L"IPAddress", this->placeholder_address.c_str());
        instance.set(L"InterfaceIndex", this->ifIndex);
        instance.write_instance(NetIPAddressTracking::get_policystore(L"ActiveStore"), WBEM_FLAG_CREATE_ONLY);
*/