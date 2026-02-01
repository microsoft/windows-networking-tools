// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <string>

enum class AppContainerName
{
	None,
	FullName,
	FamilyName
};

struct AppContainerPackage
{
	std::wstring name;
	std::wstring full_name;
	std::wstring full_name_sid;
	std::wstring family_name;
	std::wstring family_name_sid;
	std::wstring publisher;
	std::wstring publisher_id;
	std::wstring resource_id;
	std::wstring architecture;

	struct Version
	{
		uint16_t major;
		uint16_t minor;
		uint16_t build;
		uint16_t revision;
	} version;
};

void LoadAllAppPackages();
void PrintAllAppPackages();
void PrintFirewallRulesReferencingAppPackages();
const std::vector<AppContainerPackage>& ReadAllAppPackages() noexcept;
std::tuple<std::wstring, AppContainerName> FindPackageSid(PCWSTR package_sid) noexcept;
