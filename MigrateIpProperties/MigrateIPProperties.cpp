// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdio>
#include <exception>
#include <iostream>
#include <string>

#include <windows.h>

#include "ctWmiInstance.hpp"

#include "MigrateIpInterfaces.h"
#include "MigrateIpAddresses.h"
#include "MigrateIpRoutes.h"

#include <wil/com.h>
#include <wil/resource.h>



static void PrintUsage() noexcept
{
	std::printf(
		"MigrateIpProperties.exe\n"
		"Reads and displays the properties of MSFT_NetIPInterface and MSFT_NetIPAddress from a specified network interface.\n"
		"\n"
		"Usage: MigrateIpProperties.exe <InterfaceIndex>\n"
		"     : InterfaceIndex specifies the index of the network interface to query\n");
}

int __cdecl main(int, char**)
try
{
	PrintUsage();

	const auto co_init = wil::CoInitializeEx();

	// prompt the user to enter the index of the network interface they want to query properties for
	uint32_t interfaceIndex = 0;
	std::wcout << L"Enter the index of the network interface: ";
	std::wcin >> interfaceIndex;
	auto properties = MigrateIpInterfaceProperties(interfaceIndex);

	// write the properties - in this case back to the same interface for demonstration purposes
	properties.ActiveStoreProperties[0].InterfaceMetric.lVal++;
	properties.ActiveStoreProperties[1].InterfaceMetric.lVal++;
	WriteIPInterfaceProperties(properties);

	MigrateIpAddressProperties(interfaceIndex);
	MigrateIpRouteProperties(interfaceIndex);
}
catch (const std::exception& e)
{
	std::printf("\n\n** Exception : %hs\n", e.what());
}
