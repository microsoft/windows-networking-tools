// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include <windows.h>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Management.Deployment.h>


#include "AppContainers.h"
#include "NormalizedString.h"

static std::vector<AppContainerPackage> g_app_packages;

static const std::vector<AppContainerPackage>& ReadAllAppPackages() noexcept
{
	return g_app_packages;
}

void LoadAllAppPackages() noexcept
try
{
	const winrt::Windows::Management::Deployment::PackageManager packageManager;
	const auto packages = packageManager.FindPackages();
	for (auto package : packages)
	{
		AppContainerPackage app_package{ package.Id() };

		switch (package.Id().Architecture())
		{
		case winrt::Windows::System::ProcessorArchitecture::X86:
			app_package.architecture = L"x86";
			break;
		case winrt::Windows::System::ProcessorArchitecture::Arm:
			app_package.architecture = L"ARM";
			break;
		case winrt::Windows::System::ProcessorArchitecture::X64:
			app_package.architecture = L"x64";
			break;
		case winrt::Windows::System::ProcessorArchitecture::Neutral:
			app_package.architecture = L"Neutral";
			break;
		case winrt::Windows::System::ProcessorArchitecture::Arm64:
			app_package.architecture = L"ARM64";
			break;
		case winrt::Windows::System::ProcessorArchitecture::X86OnArm64:
			app_package.architecture = L"x86OnARM64";
			break;
		default:
			app_package.architecture = L"Unknown";
			break;
		}

		g_app_packages.emplace_back(std::move(app_package));
	}
}
catch (const winrt::hresult_error& ex)
{
	std::wcerr << L"Failed to load app packages: " << ex.message().c_str() << L" (0x" << std::hex << ex.code() << L")" << std::endl;
}
catch (const std::exception& ex)
{
	std::cerr << "Failed to load app packages: " << ex.what() << std::endl;
}

void PrintAllAppPackages()
{
	for (auto& package : g_app_packages)
	{
		std::wprintf(L"\n");
		std::wprintf(L"Package: %ws\n", package.name.value.c_str());
		std::wprintf(L"  Version: %u.%u.%u.%u\n",
			package.version.major,
			package.version.minor,
			package.version.build,
			package.version.revision);
		std::wprintf(L"  Architecture: %ws\n", package.architecture.c_str());
		std::wprintf(L"  ResourceId: %ws\n", package.resource_id.value.c_str());
		std::wprintf(L"  Publisher: %ws\n", package.publisher.value.c_str());
		std::wprintf(L"  PublisherId: %ws\n", package.publisher_id.value.c_str());
		std::wprintf(L"  FullName: %ws\n", package.full_name.value.c_str());
		std::wprintf(L"   - FullName SID: %ws\n", package.full_name_sid.c_str());
		std::wprintf(L"  FamilyName: %ws\n", package.family_name.value.c_str());
		std::wprintf(L"   - FamilyName SID: %ws\n", package.family_name_sid.c_str());
	}
}

// return {family_name_sid, AppContainerName}
std::tuple<std::wstring, AppContainerName> FindPackageSid(PCWSTR package_sid) noexcept
{
	const auto& app_packages = ReadAllAppPackages();
	for (const auto& package : app_packages)
	{
		if (package.family_name_sid == package_sid)
		{
			return { package.family_name_sid, AppContainerName::SID };
		}
		if (package.full_name_sid == package_sid)
		{
			DebugBreak();
		}
	}
	return { {}, AppContainerName::None };
}

// return {family_name, AppContainerName}
std::tuple<std::wstring, AppContainerName> FindPackageFamilyName(const NormalizedString& package_family_name) noexcept
{
	const auto& app_packages = ReadAllAppPackages();
	for (const auto& package : app_packages)
	{
		if (package.family_name == package_family_name)
		{
			return { package.family_name.value, AppContainerName::FamilyName };
		}
		if (package.full_name == package_family_name)
		{
			DebugBreak();
		}
	}
	return { {}, AppContainerName::None };
}
