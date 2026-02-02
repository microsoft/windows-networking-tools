// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include <windows.h>
#include <sddl.h>
#include <userenv.h>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Management.Deployment.h>

#include <wil/resource.h>

#include "AppContainers.h"

#include "FirewallRules.h"
#include "FwDiagnose.h"

static std::vector<AppContainerPackage> g_app_packages;

static std::tuple<HRESULT, std::wstring> ResolveAppContainerNameToSid(const std::wstring& name, AppContainerName container_name_type) noexcept
{
	wil::unique_sid app_container_sid{};
	const auto hr = DeriveAppContainerSidFromAppContainerName(name.c_str(), &app_container_sid);
	if (FAILED(hr))
	{
		if (DebugOutputEnabled())
		{
			std::printf("  -- Failed to derive AppContainer SID from FullName : 0x%x\n", hr);
		}
		return std::make_tuple(hr, std::wstring{});
	}

	wil::unique_hlocal_string sid_string{};
	if (!ConvertSidToStringSidW(app_container_sid.get(), &sid_string))
	{
		const auto gle = GetLastError();
		if (DebugOutputEnabled())
		{
			std::printf("  -- Failed to convert AppContainer SID to string. Error: 0x%x\n", gle);
		}
		return std::make_tuple(HRESULT_FROM_WIN32(gle), std::wstring{});
	}

	if (DebugOutputEnabled())
	{
		std::printf("  AppContainer SID from %ws (%ws) : %ws\n",
			name.c_str(),
			(container_name_type == AppContainerName::FullName ? L"FullName" : L"FamilyName"),
			sid_string.get());
	}

	return std::make_tuple(S_OK, std::wstring{ sid_string.get() });
}

void LoadAllAppPackages()
{
	const winrt::Windows::Management::Deployment::PackageManager packageManager;
	const auto packages = packageManager.FindPackages();
	for (auto package : packages)
	{
		AppContainerPackage app_package{};
		app_package.name = package.Id().Name().c_str();
		app_package.full_name = package.Id().FullName().c_str();
		app_package.family_name = package.Id().FamilyName().c_str();
		app_package.publisher = package.Id().Publisher().c_str();
		app_package.publisher_id = package.Id().PublisherId().c_str();
		app_package.resource_id = package.Id().ResourceId().c_str();
		app_package.version =
		{
			.major = package.Id().Version().Major,
			.minor = package.Id().Version().Minor,
			.build = package.Id().Version().Build,
			.revision = package.Id().Version().Revision,
		};

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

		const auto [full_name_hr, full_name_sid] = ResolveAppContainerNameToSid(app_package.full_name, AppContainerName::FullName);
		if (SUCCEEDED(full_name_hr))
		{
			app_package.full_name_sid = std::move(full_name_sid);
		}

		const auto [family_name_hr, family_name_sid] = ResolveAppContainerNameToSid(app_package.family_name, AppContainerName::FamilyName);
		if (SUCCEEDED(family_name_hr))
		{
			app_package.family_name_sid = std::move(family_name_sid);
		}

		g_app_packages.emplace_back(std::move(app_package));
	}
}

void PrintAllAppPackages()
{
	for (auto package : g_app_packages)
	{
		std::wprintf(L"Package: %ws\n", package.name.c_str());
		std::wprintf(L"  Version: %u.%u.%u.%u\n",
			package.version.major,
			package.version.minor,
			package.version.build,
			package.version.revision);
		std::wprintf(L"  Architecture: %ws\n", package.architecture.c_str());
		std::wprintf(L"  ResourceId: %ws\n", package.resource_id.c_str());
		std::wprintf(L"  Publisher: %ws\n", package.publisher.c_str());
		std::wprintf(L"  PublisherId: %ws\n", package.publisher_id.c_str());
		std::wprintf(L"  FullName: %ws\n", package.full_name.c_str());
		std::wprintf(L"   - FullName SID: %ws\n", package.full_name_sid.c_str());
		std::wprintf(L"  FamilyName: %ws\n", package.family_name.c_str());
		std::wprintf(L"   - FamilyName SID: %ws\n", package.family_name_sid.c_str());
	}
}

void PrintFirewallRulesReferencingAppPackages()
{
	std::vector<std::wstring> app_isolation_rules_without_package_id_231_or_earlier{};
	std::vector<std::wstring> app_isolation_rules_without_package_id_or_pfn_after_231{};

	std::vector<std::wstring> app_isolation_rules_with_package_id_231_or_earlier{};
	std::vector<std::wstring> app_isolation_rules_with_package_id_after_231{};
	std::vector<std::wstring> app_isolation_rules_with_pfn_after_231{};
	// uint32_t count = 0;
	for (const auto& [policy_store, rule, requestedRuleVersion] : GetRulesWithAppPackages())
	{
		if (policy_store == "Application-Isolation")
		{
			if (rule->wSchemaVersion > FW_BINARY_VERSION_31 && rule->wszPackageFamilyName)
			{
				app_isolation_rules_with_pfn_after_231.emplace_back(rule->wszRuleId);
			}
			else if (rule->wszPackageId)
			{
				// we are reading the versioning from the rule, not the requested version
				// as we are only counting rules
				// we cannot read the fields in the structure without looking at requestedRuleVersion
				if (rule->wSchemaVersion <= FW_BINARY_VERSION_31)
				{
					app_isolation_rules_with_package_id_231_or_earlier.emplace_back(rule->wszRuleId);
				}
				else
				{
					app_isolation_rules_with_package_id_after_231.emplace_back(rule->wszRuleId);
				}
			}
			else
			{
				if (rule->wSchemaVersion <= FW_BINARY_VERSION_31)
				{
					// Schema version 2.31 or earlier did not support PackageFamilyName in the FW_RULE structure
					app_isolation_rules_without_package_id_231_or_earlier.emplace_back(rule->wszRuleId);
				}
				else
				{
					app_isolation_rules_without_package_id_or_pfn_after_231.emplace_back(rule->wszRuleId);
				}
			}
		}

		/*
		if (!rule->wszName)
		{
			wprintf(L"Rule %lu: Rule has no name (packageId %ws) ***\n",
				count,
				rule->wszPackageId);
			++count;
			continue;
		}

		if (!rule->wszPackageId)
		{
			if (rule->wszName[0] == L'@')
			{
				if (!rule->wszLocalApplication)
				{
					wprintf(L"Rule %lu: %ws [no packageId, but looks like an app-package rule]\n",
						count,
						rule->wszName);
					++count;
				}
			}
			else
			{
				wprintf(L"Rule %lu: %ws [no packageId]\n",
					count,
					rule->wszName);
				++count;
			}
		}
		else
		{
			wprintf(L"Rule %lu: %ws [packageId %ws]\n",
				count,
				rule->wszName,
				rule->wszPackageId);
		}
		*/
	}

	/*
	std::vector<std::wstring> app_isolation_rules_without_package_id_231_or_earlier{};
	std::vector<std::wstring> app_isolation_rules_without_package_id_or_pfn_after_231{};

	std::vector<std::wstring> app_isolation_rules_with_package_id_231_or_earlier{};
	std::vector<std::wstring> app_isolation_rules_with_package_id_after_231{};
	std::vector<std::wstring> app_isolation_rules_with_pfn_after_231{};
    */

	wprintf(L"*** Firewall Rules in Application-Isolation Store with a PFN version after 2.31 [%llu rules] ***\n", app_isolation_rules_with_pfn_after_231.size());
	/*
	for (const auto& rule_id : app_isolation_rules_with_pfn_after_231)
	{
		wprintf(L"  RuleId: %ws\n", rule_id.c_str());
	}
	wprintf(L"\n\n");
    */

	wprintf(L"*** Firewall Rules in Application-Isolation Store with a Package ID and no PFN version after 2.31 [%llu rules] ***\n", app_isolation_rules_with_package_id_after_231.size());
	/*
	for (const auto& rule_id : app_isolation_rules_with_package_id_after_231)
	{
		wprintf(L"  RuleId: %ws\n", rule_id.c_str());
	}
	wprintf(L"\n\n");
    */

	wprintf(L"*** Firewall Rules in Application-Isolation Store with a Package ID (PFN not supported) version 2.31 or earlier [%llu rules] ***\n", app_isolation_rules_with_package_id_231_or_earlier.size());
	/*
	for (const auto& rule_id : app_isolation_rules_with_package_id_231_or_earlier)
	{
		wprintf(L"  RuleId: %ws\n", rule_id.c_str());
	}
	wprintf(L"\n\n");
	*/

	wprintf(L"*** Firewall Rules in Application-Isolation Store without a Package ID or PFN version after 2.31 [%llu rules] ***\n", app_isolation_rules_without_package_id_or_pfn_after_231.size());
	/*
	for (const auto& rule_id : app_isolation_rules_without_package_id_or_pfn_after_231)
	{
		wprintf(L"  RuleId: %ws\n", rule_id.c_str());
	}
	*/

    wprintf(L"*** Firewall Rules in Application-Isolation Store without a Package ID (PFN not supported) version 2.31 or earlier [%llu rules] ***\n", app_isolation_rules_without_package_id_231_or_earlier.size());
	/*
	for (const auto& rule_id : app_isolation_rules_without_package_id_231_or_earlier)
	{
		wprintf(L"  RuleId: %ws\n", rule_id.c_str());
	}
	wprintf(L"\n\n");
	*/
}

const std::vector<AppContainerPackage>& ReadAllAppPackages() noexcept
{
	return g_app_packages;
}

// return {family_name_sid, AppContainerName}
std::tuple<std::wstring, AppContainerName> FindPackageSid(PCWSTR package_sid) noexcept
{
	const auto& app_packages = ReadAllAppPackages();
	for (const auto package : app_packages)
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
std::tuple<std::wstring, AppContainerName> FindPackageFamilyName(PCWSTR package_family_name) noexcept
{
	const auto& app_packages = ReadAllAppPackages();
	for (const auto package : app_packages)
	{
		if (package.family_name == package_family_name)
		{
			return { package.family_name, AppContainerName::FamilyName };
		}
		if (package.full_name == package_family_name)
		{
			DebugBreak();
		}
	}
	return { {}, AppContainerName::None };
}
