// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdio>
#include <exception>
#include <string>

#include <windows.h>

#include "MigrateIpInterfaces.h"
#include "MigrateIpAddresses.h"
#include "MigrateIpRoutes.h"

#include <wil/com.h>
#include <wil/resource.h>



static void PrintUsage() noexcept
{
	std::printf(
		"\nMigrateIpProperties.exe\n"
		"\tMigrates properties of MSFT_NetIPInterface, migrates static MSFT_NetIPAddress objects, and migrates MSFTNetRoute objects from one network interface to another.\n"
		"\nUsage: MigrateIpProperties.exe <from-ifIndex> <to-ifIndex>\n"
	    "\n");
}

int __cdecl main(int argc, char** argv)
{
	if (argc != 3)
	{
		PrintUsage();
		return 1;
	}
	uint32_t fromInterfaceIndex{};
	uint32_t toInterfaceIndex{};

	try
	{
		fromInterfaceIndex = std::stoul(argv[1]);
		toInterfaceIndex = std::stoul(argv[2]);
	}
	catch (...)
	{
		PrintUsage();
		return 1;
	}

	const auto co_init = wil::CoInitializeEx();

	WriteIPInterfaceProperties(ReadIPInterfaceProperties(fromInterfaceIndex), toInterfaceIndex);
	WriteIPAddresses(ReadIPAddresses(fromInterfaceIndex), toInterfaceIndex);
	WriteIPRoutes(ReadIPRoutes(fromInterfaceIndex), toInterfaceIndex);
}
