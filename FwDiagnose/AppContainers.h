// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <string>

#include <windows.h>
#include <sddl.h>
#include <userenv.h>

#include <winrt/Windows.ApplicationModel.h>

#include "FwDiagnose.h"
#include "NormalizedString.h"

#include <wil/resource.h>

enum class AppContainerName
{
	None,
	SID,
	FullName,
	FamilyName
};

struct AppContainerPackage
{
	AppContainerPackage(const AppContainerPackage&) = delete;
	AppContainerPackage& operator=(const AppContainerPackage&) = delete;
	AppContainerPackage(AppContainerPackage&&) noexcept = default;
	AppContainerPackage& operator=(AppContainerPackage&&) noexcept = default;
	~AppContainerPackage() = default;

	// callers are required to call Create() to create an instance
	explicit AppContainerPackage(const winrt::Windows::ApplicationModel::PackageId& package) :
		name(NormalizedString::Create(package.Name().c_str())),
		full_name(NormalizedString::Create(package.FullName().c_str())),
		family_name(NormalizedString::Create(package.FamilyName().c_str())),
		publisher(NormalizedString::Create(package.Publisher().c_str())),
		publisher_id(NormalizedString::Create(package.PublisherId().c_str())),
		resource_id(NormalizedString::Create(package.ResourceId().c_str())),
		version(
			{
				.major = package.Version().Major,
				.minor = package.Version().Minor,
				.build = package.Version().Build,
				.revision = package.Version().Revision,
			})
	{
		ResolveAppContainerNameToSid(full_name.value.c_str(), AppContainerName::FullName);
		ResolveAppContainerNameToSid(family_name.value.c_str(), AppContainerName::FamilyName);
	}

	NormalizedString name;
	NormalizedString full_name;
	std::wstring full_name_sid;

	NormalizedString family_name;
	std::wstring family_name_sid;

	NormalizedString publisher;
	NormalizedString publisher_id;
	NormalizedString resource_id;

	std::wstring architecture{};

	struct Version
	{
		uint16_t major{};
		uint16_t minor{};
		uint16_t build{};
		uint16_t revision{};
	} version{};

private:
	void ResolveAppContainerNameToSid(PCWSTR app_container_name, AppContainerName container_name_type) noexcept
	{
		wil::unique_sid app_container_sid{};
		const auto hr = DeriveAppContainerSidFromAppContainerName(app_container_name, &app_container_sid);
		if (FAILED(hr))
		{
			LOG_HR_MSG(hr, "DeriveAppContainerSidFromAppContainerName failed");
			if (DebugOutputEnabled())
			{
				std::printf("  -- Failed to derive AppContainer SID from FullName : 0x%x\n", hr);
			}
			return;
		}

		wil::unique_hlocal_string sid_string{};
		if (!ConvertSidToStringSidW(app_container_sid.get(), &sid_string))
		{
			const auto gle = GetLastError();
			LOG_HR_MSG(HRESULT_FROM_WIN32(gle), "ConvertSidToStringSidW failed");
			if (DebugOutputEnabled())
			{
				std::printf("  -- Failed to convert AppContainer SID to string. Error: 0x%x\n", gle);
			}
			return;
		}

		if (DebugOutputEnabled())
		{
			std::printf("  AppContainer SID from %ws (%ws) : %ws\n",
				name.value.c_str(),
				(container_name_type == AppContainerName::FullName ? L"FullName" : L"FamilyName"),
				sid_string.get());
		}

		if (container_name_type == AppContainerName::FullName)
		{
			full_name_sid = sid_string.get();
		}
		else if (container_name_type == AppContainerName::FamilyName)
		{
			family_name_sid = sid_string.get();
		}
		else
		{
			FAIL_FAST();
		}
	}
};

void LoadAllAppPackages() noexcept;
void PrintAllAppPackages();

std::tuple<std::wstring, AppContainerName> FindPackageSid(PCWSTR package_sid) noexcept;
std::tuple<std::wstring, AppContainerName> FindPackageFamilyName(const NormalizedString& package_family_name) noexcept;
