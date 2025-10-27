// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <vector>
#include <string>
#include <optional>
#include <tuple>
#include <ranges>
#include <iostream>

#include <Windows.h>

#include "FwDiagnose.h"
#include "firewall.h"
#include "FirewallRules.h"
#include "NormalizedFirewallRule.h"

#include <wil/stl.h>
#include <wil/resource.h>
#include <wil/registry.h>

static HMODULE g_FirewallApiModule = nullptr;
static decltype(FWOpenPolicyStore)* g_FWOpenPolicyStore = nullptr;
static decltype(FWClosePolicyStore)* g_FWClosePolicyStore = nullptr;
static decltype(FWEnumFirewallRules)* g_FWEnumFirewallRules = nullptr;
static decltype(FWFreeFirewallRules)* g_FWFreeFirewallRules = nullptr;
static decltype(FWDeleteFirewallRule)* g_FWDeleteFirewallRule = nullptr;

static FW_POLICY_STORE_HANDLE g_policyStore = nullptr;

static void PrintDeletionHeader(PCSTR str) noexcept
{
	std::printf(
		"     %s - will prompt for input (y/n/s/a)\n"
		"     - indicate 'Y' to delete duplicates of the one rule prompted\n"
		"     - indicate 'N' to not delete duplicates of the one rule prompted\n"
		"     - indicate 'S' to SKIP deleting any more rules from this store\n"
		"     - indicate 'A' to delete ALL duplicate rules from this store without further prompts\n",
		str);
}
static PCSTR DeletionPrompt = "Delete all duplicates of this rule";

void LoadFirewallFunctions()
{
	g_FirewallApiModule = LoadLibraryW(L"FirewallAPI.dll");
	THROW_LAST_ERROR_IF(!g_FirewallApiModule);

	// Load the necessary functions from the FirewallAPI DLL
	// as documented https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/230d1ae7-b42e-4d9c-b997-b1463aaa0ded
	// and related RRPC protocol documentation
	uint32_t gle = NO_ERROR;
	g_FWOpenPolicyStore = reinterpret_cast<decltype(FWOpenPolicyStore)*>(GetProcAddress(g_FirewallApiModule, "FWOpenPolicyStore"));  // NOLINT(clang-diagnostic-cast-function-type-strict)
	if (!g_FWOpenPolicyStore)
	{
		gle = GetLastError();
	}
	g_FWClosePolicyStore = reinterpret_cast<decltype(FWClosePolicyStore)*>(GetProcAddress(g_FirewallApiModule, "FWClosePolicyStore"));  // NOLINT(clang-diagnostic-cast-function-type-strict)
	if (!g_FWClosePolicyStore)
	{
		gle = GetLastError();
	}
	g_FWEnumFirewallRules = reinterpret_cast<decltype(FWEnumFirewallRules)*>(GetProcAddress(g_FirewallApiModule, "FWEnumFirewallRules"));  // NOLINT(clang-diagnostic-cast-function-type-strict)
	if (!g_FWEnumFirewallRules)
	{
		gle = GetLastError();
	}
	g_FWFreeFirewallRules = reinterpret_cast<decltype(FWFreeFirewallRules)*>(GetProcAddress(g_FirewallApiModule, "FWFreeFirewallRules"));  // NOLINT(clang-diagnostic-cast-function-type-strict)
	if (!g_FWFreeFirewallRules)
	{
		gle = GetLastError();
	}
	g_FWDeleteFirewallRule = reinterpret_cast<decltype(FWDeleteFirewallRule)*>(GetProcAddress(g_FirewallApiModule, "FWDeleteFirewallRule"));  // NOLINT(clang-diagnostic-cast-function-type-strict)
	if (!g_FWDeleteFirewallRule)
	{
		gle = GetLastError();
	}

	THROW_IF_WIN32_ERROR(gle);
}

bool HasFirewallAdminAccess()
{
	FW_POLICY_STORE_HANDLE test_handle = nullptr;
	ChronoTimer timer;
	timer.start("OpenPolicyStore");
	const auto openStoreError = g_FWOpenPolicyStore(
		FW_CURRENT_BINARY_VERSION,
		nullptr,
		FW_STORE_TYPE_LOCAL,
		FW_POLICY_ACCESS_RIGHT_READ_WRITE,
		FW_POLICY_STORE_FLAGS_NONE,
		&test_handle);
	if (openStoreError != ERROR_SUCCESS)
	{
		if (openStoreError == ERROR_ACCESS_DENIED)
		{
			return false;
		}
		THROW_WIN32(openStoreError);
	}
	timer.end();

	g_FWClosePolicyStore(test_handle);
	return true;
}
HRESULT LoadFirewallRulesFromStore(FirewallPolicyObjects& policy)
{
	if (g_policyStore)
	{
		const auto close_error = g_FWClosePolicyStore(g_policyStore);
		if (close_error != ERROR_SUCCESS)
		{
			std::printf("  *** Failed to close previous firewall policy store. Error: 0x%lx\n", close_error);
		}
		g_policyStore = nullptr;
	}

	ChronoTimer timer;
	timer.start("OpenPolicyStore");
	const auto openStoreError = g_FWOpenPolicyStore(
		FW_CURRENT_BINARY_VERSION,
		nullptr,
		policy.type,
		CleanBrokenRulesEnabled() ? FW_POLICY_ACCESS_RIGHT_READ_WRITE : FW_POLICY_ACCESS_RIGHT_READ,
		FW_POLICY_STORE_FLAGS_NONE,
		&g_policyStore);
	if (openStoreError != ERROR_SUCCESS)
	{
		if (openStoreError == ERROR_ACCESS_DENIED)
		{
			std::printf("\n  Administrative privileges required - try running from an elevated Administrator command prompt.");
		}
		else if (openStoreError == ERROR_FILE_NOT_FOUND)
		{
			std::printf("\n  The %s Firewall Policy Store does not exist on this system.", policy.type_string);
		}
		else
		{
			std::printf("\n  Failed to open firewall policy store. Error: 0x%lx", openStoreError);
		}
		return openStoreError;
	}
	timer.end();

	timer.start("EnumFirewallRules");
	DWORD num_rules = 0;
	FW_RULE* rules = nullptr;
	const auto enumRulesError = g_FWEnumFirewallRules(
		g_policyStore,
		static_cast<DWORD>(FW_RULE_STATUS_CLASS_ALL),
		FW_PROFILE_TYPE_ALL,
		FW_ENUM_RULES_FLAG_INCLUDE_METADATA,
		&num_rules,
		&rules);
	if (enumRulesError != ERROR_SUCCESS)
	{
		std::printf("  Failed to enumerate firewall rules. Error: 0x%lx\n", enumRulesError);
		THROW_WIN32(enumRulesError);
	}
	timer.end();

	// cannot FWFreeFirewallRules - since we keep those pointers around to read later

	timer.start("Normalizing Firewall rules into a vector");
	FW_RULE* rule_iterator = rules;
	while (rule_iterator)
	{
		policy.normalizedRules.emplace_back(NormalizedFirewallRule::BuildFromFWRule(rule_iterator));
		rule_iterator = rule_iterator->pNext;
	}
	timer.end();

	FAIL_FAST_IF(num_rules != policy.normalizedRules.size());

	// std::printf("  * Found a total of %zu Firewall rules\n", policy.normalizedRules.size());
	if (!policy.normalizedRules.empty())
	{
		timer.start("Sorting Firewall rules");
		std::ranges::sort(
			policy.normalizedRules,
			[](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
			{
				return RuleDetailsComparison(lhs, rhs) < 0;
			}
		);
		timer.end();
		if (VerboseOutputEnabled())
		{
			std::printf("\n");
		}
	}

	return S_OK;
}

std::vector<DuplicateRuleDetails> CheckForDuplicateRules(std::vector<NormalizedFirewallRule>& normalized_rules)
{
	std::vector<std::wstring> verbose_output_of_duplicate_strings;
	std::vector<DuplicateRuleDetails> duplicate_rules;
	for (auto currentIterator = normalized_rules.begin(); currentIterator != normalized_rules.end();)
	{
		// the predicate used for adjacent_find is pivoted on whether the user asked for an exact match or not
		currentIterator = std::adjacent_find(
			currentIterator,
			normalized_rules.end(),
			[](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
			{
				return RuleDetailsComparison(lhs, rhs) == 0;
			}
		);

		if (currentIterator == normalized_rules.end())
		{
			// if adjacent_find returns the end iterator, there are no more adjacent entries that match
			// in which case we should break out of the for loop
			break;
		}

		const auto duplicate_rule_begin = currentIterator;

		// currentIterator is currently pointing to the first of x number of duplicate rules
		// iterate through normalized_rules until we hit the end of the vector
		// or until RuleDetailsComparison returns false (i.e., we found the iterator past the last duplicate)
		while (currentIterator != normalized_rules.end())
		{
			if (currentIterator + 1 == normalized_rules.end())
			{
				break;
			}

			if (RuleDetailsComparison(*currentIterator, *(currentIterator + 1)) != 0)
			{
				break;
			}

			++currentIterator;
		}

		// incrementing currentIterator so it points to next-rule-past the one that matched
		// unless we hit the end of the vector
		if (currentIterator != normalized_rules.end())
		{
			++currentIterator;
		}

		const auto duplicate_rule_end = currentIterator;

		duplicate_rules.emplace_back(
			DuplicateRuleDetails{
				.duplicate_rule_begin = duplicate_rule_begin,
				.duplicate_rule_end = duplicate_rule_end
			});

		std::wstring verbose_string;
		if (duplicate_rule_begin->fwRule->wszLocalApplication)
		{
			verbose_string =
				wil::str_printf<std::wstring>(
					L"%ls:  %ls (Application-exe: '%ls')\n",
					duplicate_rule_begin->ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					duplicate_rule_begin->ruleName.value.empty() ? duplicate_rule_begin->fwRule->wszRuleId : duplicate_rule_begin->ruleName.value.c_str(),
					duplicate_rule_begin->fwRule->wszLocalApplication);
		}
		else
		{
			verbose_string =
				wil::str_printf<std::wstring>(
					L"%ls:  %ls\n",
					duplicate_rule_begin->ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					duplicate_rule_begin->ruleName.value.empty() ? duplicate_rule_begin->fwRule->wszRuleId : duplicate_rule_begin->ruleName.value.c_str());
		}

		if (std::ranges::find(verbose_output_of_duplicate_strings, verbose_string) == verbose_output_of_duplicate_strings.end())
		{
			verbose_output_of_duplicate_strings.emplace_back(std::move(verbose_string));
		}
	}

	size_t derived_total = 0;
	for (const auto& rule : duplicate_rules)
	{
		derived_total += rule.duplicate_rule_end - rule.duplicate_rule_begin;
	}

	if (VerboseOutputEnabled() || !duplicate_rules.empty())
	{
		std::printf("  * Summary of duplicate analysis of firewall rules:\n");
		std::printf("   - count of all duplicate rules: %zu\n", derived_total);
		std::printf("   - count of unique rules with duplicates: %zu\n", duplicate_rules.size());
		if (VerboseOutputEnabled() && !verbose_output_of_duplicate_strings.empty())
		{
			std::printf("   - unique rule names of duplicate rules:\n");
			for (const auto& verbose_output : verbose_output_of_duplicate_strings)
			{
				std::printf("       %ls", verbose_output.c_str());
			}
		}
	}
	return duplicate_rules;
}

void DeleteDuplicateRules(const std::vector<DuplicateRuleDetails>& duplicate_rules)
{
	bool printed_deletion_header = false;
	bool delete_all_with_no_more_prompts = false;

	for (const auto& duplicate_rule : duplicate_rules)
	{
		const auto duplicate_rule_total = std::distance(duplicate_rule.duplicate_rule_begin, duplicate_rule.duplicate_rule_end);
		FAIL_FAST_IF(duplicate_rule_total == 0);

		if (!printed_deletion_header)
		{
			printed_deletion_header = true;
			PrintDeletionHeader("Deleting duplicate rules");
		}

		std::printf(
			"\n"
			"     %zd duplicates of this rule [%ls:  %ls]\n",
			duplicate_rule_total,
			duplicate_rule.duplicate_rule_begin->ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			duplicate_rule.duplicate_rule_begin->ruleName.value.empty() ? duplicate_rule.duplicate_rule_begin->fwRule->wszRuleId : duplicate_rule.duplicate_rule_begin->ruleName.value.c_str());

		if (!delete_all_with_no_more_prompts)
		{
			switch (PromptForDeletion(DeletionPrompt))
			{
			case PromptResponse::Yes:
				// continue to delete the duplicates of this rule
				break;

			case PromptResponse::No:
				std::printf("       - Skipping this rule\n");
				continue;

			case PromptResponse::Skip:
				std::printf("       - Skipping the remainder of the duplicate rules in this store\n");
				return;

			case PromptResponse::All:
				std::printf("       - Deleting all duplicate rules in this store\n");
				delete_all_with_no_more_prompts = true;
				break;
			}
		}

		// if the names are not the same, ask the user which to keep
		bool allNamesMatch = true;
		for (auto iter = duplicate_rule.duplicate_rule_begin; iter != duplicate_rule.duplicate_rule_end; ++iter)
		{
			auto next = iter + 1;
			if (next == duplicate_rule.duplicate_rule_end)
			{
				break;
			}
			if (iter->ruleName != next->ruleName)
			{
				allNamesMatch = false;
				break;
			}
		}

		// by default keep the first rule
		// if names don't match, ask the user which rule to keep
		uint32_t rule_to_keep = 1;
		if (!allNamesMatch)
		{
			uint32_t rule_count = 0;
			uint32_t rule_listing = 0;

			std::printf("\n     Duplicate rules have different names. Please choose which to keep:\n");

			// cache the rule names so we don't present the same name multiple times
			struct DuplicateRuleDetails
			{
				NormalizedString rule_name;
				uint32_t rule_count;
				uint32_t rule_listing;
			};

			// duplicate_rule_details will contain all unique names for duplicate rules
			// this is to preset the user with a list of unique rule names to ask which to keep
			// since we will delete all but one of the duplicates
			std::vector<DuplicateRuleDetails> duplicate_rule_details;
			for (const auto& rule : std::ranges::subrange(duplicate_rule.duplicate_rule_begin, duplicate_rule.duplicate_rule_end))
			{
				++rule_count;

				bool rule_name_exists = false;
				for (const auto& rule_detail : duplicate_rule_details)
				{
					if (rule_detail.rule_name == rule.ruleName)
					{
						// already listed this rule name, skip
						rule_name_exists = true;
						break;
					}
				}

				// a new unique name for a duplicate rule
				if (!rule_name_exists)
				{
					++rule_listing;
					duplicate_rule_details.emplace_back(
						DuplicateRuleDetails{
							.rule_name = NormalizedString::Copy(rule.ruleName),
							.rule_count = rule_count,
							.rule_listing = rule_listing
						});
				}
			}

			// sort the rule names alphabetically to make presenting to the user nicer
			std::ranges::sort(
				duplicate_rule_details,
				[](const DuplicateRuleDetails& lhs, const DuplicateRuleDetails& rhs)
				{
					return lhs.rule_name < rhs.rule_name;
				});

			// after sorting by name, renumber them
			rule_listing = 0;
			for (auto& rule_detail : duplicate_rule_details)
			{
				rule_detail.rule_listing = ++rule_listing;
				std::printf("       %u. %ls\n", rule_detail.rule_listing, rule_detail.rule_name.value.c_str());
			}

			// now ask the user which rule to keep
			std::wstring userInput;
			for (;;)
			{
				std::printf("       Enter the number of the rule to keep: ");
				userInput.clear();
				std::getline(std::wcin, userInput);
				const auto entered_rule_listing = std::wcstoul(userInput.c_str(), nullptr, 10);
				if (entered_rule_listing < 1 || entered_rule_listing > rule_listing)
				{
					// invalid, ask the user again
					continue;
				}

				// they chose the rule - find the rule_to_keep value matching it
				for (const auto& rule_detail : duplicate_rule_details)
				{
					if (rule_detail.rule_listing == entered_rule_listing)
					{
						rule_to_keep = rule_detail.rule_count;
						break;
					}
				}
				break;
			}
		}

		std::printf("       Deleting %zd duplicates of this rule, keeping 1\n", duplicate_rule_total - 1);

		uint32_t delete_rule_counter = 0;
		uint32_t successful_deletion_counter = 0;
		for (auto& rule : std::ranges::subrange(duplicate_rule.duplicate_rule_begin, duplicate_rule.duplicate_rule_end))
		{
			++delete_rule_counter;
			if (delete_rule_counter == rule_to_keep)
			{
				std::printf(
					"        Keeping [%ls:  %ls]\n",
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str());
				continue;
			}

			const auto deleteRuleError = g_FWDeleteFirewallRule(g_policyStore, rule.fwRule->wszRuleId);
			if (deleteRuleError != ERROR_SUCCESS)
			{
				std::printf("        Failed to delete one of the duplicate firewall rules (0x%lx) - RuleId %ls\n", deleteRuleError, rule.fwRule->wszRuleId);
			}
			else
			{
				rule.ruleDeleted = true;
				++successful_deletion_counter;
				if (DebugPrintEnabled())
				{
					std::printf("        Successfully deleted the duplicate firewall rule RuleId %ls\n", rule.fwRule->wszRuleId);
				}
			}
		}

		if (successful_deletion_counter > 0)
		{
			std::printf("        Successfully deleted %u duplicate firewall rules\n", successful_deletion_counter);
		}
	}
}

void CheckForMissingAppRules(const std::vector<NormalizedFirewallRule>& normalized_rules)
{
	size_t count_of_rules_with_local_application = 0;

	std::vector<std::wstring> verbose_output_of_error_strings;

	for (const auto& rule : normalized_rules)
	{
		if (rule.fwRule->wszLocalApplication)
		{
			++count_of_rules_with_local_application;

			if (rule.targetApplicationExists.has_value() && !rule.targetApplicationExists.value())
			{
				verbose_output_of_error_strings.emplace_back(
					wil::str_printf<std::wstring>(
						L"     Application-exe:  '%ls'  [%ls:  %ls]\n",
						rule.fwRule->wszLocalApplication,
						rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
						rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
			}
		}
	}

	if (VerboseOutputEnabled() || !verbose_output_of_error_strings.empty())
	{
		std::printf("  * Summary of application analysis of firewall rules:\n");
		std::printf("   - count of rules with an application exe: %zu\n", count_of_rules_with_local_application);
		std::printf("   - count of rules with an application exe referencing non-existing file: %zu\n", verbose_output_of_error_strings.size());
		if (VerboseOutputEnabled() && !verbose_output_of_error_strings.empty())
		{
			std::printf("   - unique rule names of rules with an application exe referencing non-existing file:\n");
			for (const auto& error_string : verbose_output_of_error_strings)
			{
				std::printf("%ls", error_string.c_str());
			}
		}
	}
}

void DeleteMissingAppRules(const std::vector<NormalizedFirewallRule>& normalized_rules)
{
	bool delete_all_with_no_more_prompts = false;
	bool printed_deletion_header = false;

	for (const auto& rule : normalized_rules)
	{
		if (rule.ruleDeleted)
		{
			continue;
		}

		if (!rule.targetApplicationExists.has_value())
		{
			// this rule was not checked for app file existence, skip it
			continue;
		}

		if (rule.targetApplicationExists == true)
		{
			continue; // verified this file exists
		}

		if (!printed_deletion_header)
		{
			printed_deletion_header = true;
			PrintDeletionHeader("Deleting rules with an application exe referencing non-existing file");
		}

		std::printf(
			"\n"
			"     Application-exe:  '%ls'  [%ls:  %ls]\n",
			rule.fwRule->wszLocalApplication,
			rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str());

		if (!delete_all_with_no_more_prompts)
		{
			switch (PromptForDeletion(DeletionPrompt))
			{
			case PromptResponse::Yes:
				// continue to delete this rule
				break;

			case PromptResponse::No:
				std::printf("       - Skipping this rule\n");
				continue;

			case PromptResponse::Skip:
				std::printf("       - Skipping the remainder of the rules with an application exe referencing non-existing file in this store\n");
				return;

			case PromptResponse::All:
				std::printf("       - Deleting all rules with an application exe referencing non-existing file in this store\n");
				delete_all_with_no_more_prompts = true;
				break;
			}
		}

		const auto deleteRuleError = g_FWDeleteFirewallRule(g_policyStore, rule.fwRule->wszRuleId);
		if (deleteRuleError != ERROR_SUCCESS)
		{
			std::printf("       - Failed to delete the firewall rule (0x%lx)\n", deleteRuleError);
		}
		else
		{
			std::printf("       - Successfully deleted the firewall rule\n");
		}
	}
}

void CheckUnresolvedUserAccountRules(std::vector<NormalizedFirewallRule>& normalized_rules, FW_STORE_TYPE store_type)
{
	const bool check_for_local_profile = store_type == FW_STORE_TYPE_APP_ISO || store_type == FW_STORE_TYPE_IF_ISO;

	/*
	 * If a SID references a non-existing user account for an App-Isolation or Interface-Isolation rule, flag it to be deleted
	 *
		> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"

		HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList
			Default    REG_EXPAND_SZ    %SystemDrive%\Users\Default
			ProfilesDirectory    REG_EXPAND_SZ    %SystemDrive%\Users
			ProgramData    REG_EXPAND_SZ    %SystemDrive%\ProgramData
			Public    REG_EXPAND_SZ    %SystemDrive%\Users\Public

		HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-12-1-910410835-1306523740-2996082354-1245529378
		HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18
		HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-19
		HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-20
		HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-99-486568272-975562994-1883531608-2732234258-332540751
	*/

	const auto convert_sid_to_name = [](PCWSTR sid_string) -> std::optional<std::tuple<std::wstring, std::wstring>>
		{
			std::wstring localUserOwnerName;
			std::wstring localUserDomainName;

			// process the local user owner string for string resources
			wil::unique_sid localUserOwnerSid;
			if (!ConvertStringSidToSid(sid_string, localUserOwnerSid.addressof()))
			{
				const auto gle = GetLastError();
				if (DebugPrintEnabled())
				{
					std::printf("Failed to ConvertStringSidToSid(%ls) (0x%lx)\n", sid_string, gle);
				}
				return std::nullopt;
			}

			DWORD localUserOwnerNameSize = 0;
			DWORD cchReferencedDomainName = 0;
			SID_NAME_USE sid_name_use{};
			if (!LookupAccountSidW(nullptr, localUserOwnerSid.get(), localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
			{
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					localUserOwnerName.resize(localUserOwnerNameSize);
					localUserDomainName.resize(cchReferencedDomainName);

					if (!LookupAccountSidW(nullptr, localUserOwnerSid.get(), localUserOwnerName.data(), &localUserOwnerNameSize, localUserDomainName.data(), &cchReferencedDomainName, &sid_name_use))
					{
						const auto gle = GetLastError();
						if (DebugPrintEnabled())
						{
							std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", sid_string, gle);
						}
						return std::nullopt;
					}

					if (DebugPrintEnabled())
					{
						if (localUserDomainName.empty())
						{
							std::printf("Successfully converted LocalUserOwner SID %ls to %ls\n", sid_string, localUserOwnerName.c_str());
						}
						else
						{
							std::printf("Successfully converted LocalUserOwner SID %ls to %ls\\%ls\n", sid_string, localUserDomainName.c_str(), localUserOwnerName.c_str());
						}
					}
				}
				else
				{
					const auto gle = GetLastError();
					if (DebugPrintEnabled())
					{
						std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", sid_string, gle);
					}
					return std::nullopt;
				}
			}
			else
			{
				// should never happen
				FAIL_FAST();
			}

			return std::make_tuple(localUserDomainName, localUserOwnerName);
		};

	std::vector<std::wstring> local_profile_sids;
	if (check_for_local_profile)
	{
		if (VerboseOutputEnabled())
		{
			std::printf(
				"  NOTE: Since this is an App-Isolation or Interface-Isolation store,\n"
				"        rules with unresolved local user profiles are unnecessary and unused,\n"
				"        as those rules are automatically recreated each time a local profile is created\n"
				"\n");
		}

		if (VerboseOutputEnabled())
		{
			std::printf("  * Querying local user profiles from the registry...\n");
		}

		const auto profile_key = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, LR"(Software\Microsoft\Windows NT\CurrentVersion\ProfileList)");
		for (const auto& key_data : wil::make_range(wil::reg::key_iterator{ profile_key.get() }, wil::reg::key_iterator{}))
		{
			auto profile_sid = key_data.name;
			const auto optional_name_conversion = convert_sid_to_name(profile_sid.c_str());
			if (optional_name_conversion.has_value())
			{
				const auto& [domain_name, user_name] = optional_name_conversion.value();
				if (VerboseOutputEnabled())
				{
					std::printf("    Local profile SID: %ls  (%ls\\%ls)\n", profile_sid.c_str(), domain_name.c_str(), user_name.c_str());
				}
				local_profile_sids.emplace_back(std::move(profile_sid));
			}
			else
			{
				if (VerboseOutputEnabled())
				{
					std::printf("    Local profile SID: %ls  (Failed to resolve the SID)\n", profile_sid.c_str());
				}
			}
		}

		if (VerboseOutputEnabled())
		{
			std::printf("\n");
		}
	}

	size_t count_of_rules_with_local_user_owner = 0;
	std::vector<std::wstring> rules_with_unknown_sid_owners;
	std::vector<std::wstring> rules_with_no_local_profile;
	for (auto& rule : normalized_rules)
	{
		if (!rule.userNameResolvedSuccessfully.has_value())
		{
			continue;
		}

		++count_of_rules_with_local_user_owner;

		if (!rule.userNameResolvedSuccessfully.value())
		{
			rules_with_unknown_sid_owners.emplace_back(
				wil::str_printf<std::wstring>(
					L"    Unresolved SID:  '%ls'  [%ls:  %ls]\n",
					rule.fwRule->wszLocalUserOwner,
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
		else if (check_for_local_profile)
		{
			// name resolved - check if there's a matching local profile
			const auto found_local_user_owner_profile =
				std::ranges::find_if(
					local_profile_sids,
					[&](const std::wstring& sid) {
						return _wcsicmp(sid.c_str(), rule.fwRule->wszLocalUserOwner) == 0;
					});

			if (found_local_user_owner_profile == local_profile_sids.cend())
			{
				rule.userNameResolvedSuccessfullyWithLocalProfile = false;
				rules_with_no_local_profile.emplace_back(
					wil::str_printf<std::wstring>(
						L"    Rule with a SID that failed to verify its local profile:  '%ls' (%ls\\%ls)\n"
						L"      [%ls:  %ls]\n",
						rule.fwRule->wszLocalUserOwner,
						rule.localUserDomainName.c_str(),
						rule.localUserOwnerName.c_str(),
						rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
						rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
			}
			else
			{
				rule.userNameResolvedSuccessfullyWithLocalProfile = true;
				if (DebugPrintEnabled())
				{
					std::printf(
						"    Rule with a SID matching a local profile:  '%ls' (%ls\\%ls)\n"
						"      [%ls:  %ls]\n",
						rule.fwRule->wszLocalUserOwner,
						rule.localUserDomainName.c_str(),
						rule.localUserOwnerName.c_str(),
						rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
						rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str());

				}
			}
		}
	}

	if (VerboseOutputEnabled() || !rules_with_unknown_sid_owners.empty() || !rules_with_no_local_profile.empty())
	{
		std::printf("  * Summary of SID owner analysis of firewall rules:\n");
		std::printf("   - count of rules with LocalUserOwner SID: %zu\n", count_of_rules_with_local_user_owner);
		std::printf("   - count of rules with LocalUserOwner SID referencing unresolved SID: %zu\n", rules_with_unknown_sid_owners.size());

		if (check_for_local_profile)
		{
			std::printf("   - count of rules with LocalUserOwner SID referencing non-existing local profile: %zu\n", rules_with_no_local_profile.size());
		}

		if (VerboseOutputEnabled())
		{
			if (!rules_with_unknown_sid_owners.empty())
			{
				std::printf("     - rules with unresolved SIDs:\n");
			}
			for (const auto& error_string : rules_with_unknown_sid_owners)
			{
				std::printf("     %ls", error_string.c_str());
			}

			if (!rules_with_no_local_profile.empty())
			{
				std::printf("     - rules with no local profile:\n");
			}
			for (const auto& error_string : rules_with_no_local_profile)
			{
				std::printf("     %ls", error_string.c_str());
			}
		}
	}
}

void DeleteUnresolvedUserAccountRules(const std::vector<NormalizedFirewallRule>& normalized_rules)
{
	bool delete_all_with_no_more_prompts = false;
	bool printed_deletion_header = false;

	for (const auto& rule : normalized_rules)
	{
		if (rule.ruleDeleted)
		{
			continue;
		}

		if (!rule.userNameResolvedSuccessfully.has_value())
		{
			// this rule was not checked for user account existence, skip it
			continue;
		}

		// prompt to delete if:
		// - rule does not have a valid user account
		// - rule has a valid user account but does not have a local profile (only for App-Isolation and Interface-Isolation stores)
		std::wstring rule_to_delete;
		if (!rule.userNameResolvedSuccessfully.value())
		{
			rule_to_delete =
				wil::str_printf<std::wstring>(
					L"\n"
					L"  - Unresolved SID '%ls'  [%ls:  %ls]\n",
					rule.fwRule->wszLocalUserOwner,
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str());
		}

		if (rule.userNameResolvedSuccessfullyWithLocalProfile.has_value())
		{
			// name resolved - only prompt if checking for local profile and rule does not have a local profile
			if (!rule.userNameResolvedSuccessfullyWithLocalProfile.value())
			{
				rule_to_delete =
					wil::str_printf<std::wstring>(
						L"\n"
						L"  - Valid SID but no local profile '%ls' (%ls\\%ls)\n"
						L"      [%ls:  %ls]\n",
						rule.fwRule->wszLocalUserOwner,
						rule.localUserDomainName.c_str(),
						rule.localUserOwnerName.c_str(),
						rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
						rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str());
			}
		}

		if (rule_to_delete.empty())
		{
			continue;
		}

		if (!printed_deletion_header)
		{
			printed_deletion_header = true;
			PrintDeletionHeader("Deleting rules with unresolved SIDs or SIDs without local profiles:\n");
		}

		std::printf("%ls", rule_to_delete.c_str());

		if (!delete_all_with_no_more_prompts)
		{
			switch (PromptForDeletion(DeletionPrompt))
			{
			case PromptResponse::Yes:
				// continue to delete this rule
				break;

			case PromptResponse::No:
				std::printf("       - Skipping this rule\n");
				continue;

			case PromptResponse::Skip:
				std::printf("       -Skipping the remainder of the rules with unresolved SIDs in this store\n");
				return;

			case PromptResponse::All:
				std::printf("       - Deleting all rules with unresolved SIDs in this store\n");
				delete_all_with_no_more_prompts = true;
				break;
			}
		}

		const auto deleteRuleError = g_FWDeleteFirewallRule(g_policyStore, rule.fwRule->wszRuleId);
		if (deleteRuleError != ERROR_SUCCESS)
		{
			std::printf("       - Failed to delete the firewall rule (0x%lx)\n", deleteRuleError);
		}
		else
		{
			std::printf("       - Successfully deleted the firewall rule\n");
		}
	}
}

void CheckForRulesWithErrorStatus(const std::vector<NormalizedFirewallRule>& normalized_rules)
{
	size_t rules_with_no_errors = 0;

	std::vector<std::wstring> verbose_rules_partially_ignored_error_strings;
	std::vector<std::wstring> verbose_rules_completely_ignored_error_strings;
	std::vector<std::wstring> verbose_rules_with_parsing_errors_error_strings;
	std::vector<std::wstring> verbose_rules_with_semantic_errors_error_strings;
	std::vector<std::wstring> verbose_rules_with_runtime_errors_error_strings;
	std::vector<std::wstring> verbose_rules_with_unknown_errors_error_strings;

	for (const auto& rule : normalized_rules)
	{
		if ((rule.fwRule->Status & FW_RULE_STATUS_OK) == FW_RULE_STATUS_OK)
		{
			++rules_with_no_errors;
		}
		else if ((rule.fwRule->Status & FW_RULE_STATUS_PARTIALLY_IGNORED) == FW_RULE_STATUS_PARTIALLY_IGNORED)
		{
			verbose_rules_partially_ignored_error_strings.emplace_back(
				wil::str_printf<std::wstring>(
					L"A rule has some fields that were not understood and ignored:  %ls:  %ls\n",
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
		else if ((rule.fwRule->Status & FW_RULE_STATUS_IGNORED) == FW_RULE_STATUS_IGNORED)
		{
			verbose_rules_completely_ignored_error_strings.emplace_back(
				wil::str_printf<std::wstring>(
					L"A rule was completely ignored:  %ls:  %ls\n",
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
		else if ((rule.fwRule->Status & FW_RULE_STATUS_PARSING_ERROR) == FW_RULE_STATUS_PARSING_ERROR)
		{
			verbose_rules_with_parsing_errors_error_strings.emplace_back(
				wil::str_printf<std::wstring>(
					L"A rule has parsing error (0x%x):  %ls:  %ls\n",
					rule.fwRule->Status,
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
		else if ((rule.fwRule->Status & FW_RULE_STATUS_SEMANTIC_ERROR) == FW_RULE_STATUS_SEMANTIC_ERROR)
		{
			verbose_rules_with_semantic_errors_error_strings.emplace_back(
				wil::str_printf<std::wstring>(
					L"A rule has semantic error (0x%x):  %ls:  %ls\n",
					rule.fwRule->Status,
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
		else if ((rule.fwRule->Status & FW_RULE_STATUS_RUNTIME_ERROR) == FW_RULE_STATUS_RUNTIME_ERROR)
		{
			verbose_rules_with_runtime_errors_error_strings.emplace_back(
				wil::str_printf<std::wstring>(
					L"A rule has runtime error (0x%x):  %ls:  %ls\n",
					rule.fwRule->Status,
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
		else
		{
			verbose_rules_with_unknown_errors_error_strings.emplace_back(
				wil::str_printf<std::wstring>(
					L"    A rule has unknown error status (0x%x):  %ls:  %ls\n",
					rule.fwRule->Status,
					rule.ruleName.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
					rule.ruleName.value.empty() ? rule.fwRule->wszRuleId : rule.ruleName.value.c_str()));
		}
	}

	if (VerboseOutputEnabled() ||
		!verbose_rules_partially_ignored_error_strings.empty() ||
		!verbose_rules_completely_ignored_error_strings.empty() ||
		!verbose_rules_with_parsing_errors_error_strings.empty() ||
		!verbose_rules_with_semantic_errors_error_strings.empty() ||
		!verbose_rules_with_runtime_errors_error_strings.empty() ||
		!verbose_rules_with_unknown_errors_error_strings.empty())
	{
		std::printf("  * Summary of status analysis of firewall rules:\n");
		std::printf("   - count of rules with no errors: %zu\n", rules_with_no_errors);

		if (VerboseOutputEnabled() || !verbose_rules_partially_ignored_error_strings.empty())
		{
			std::printf("   - count of rules with partially ignored (some fields not understood): %zu\n", verbose_rules_partially_ignored_error_strings.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& error_string : verbose_rules_partially_ignored_error_strings)
				{
					std::printf("       %ls", error_string.c_str());
				}
			}
		}

		if (VerboseOutputEnabled() || !verbose_rules_completely_ignored_error_strings.empty())
		{
			std::printf("   - count of rules with completely ignored (newer schema with unknown fields): %zu\n", verbose_rules_completely_ignored_error_strings.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& error_string : verbose_rules_completely_ignored_error_strings)
				{
					std::printf("       %ls", error_string.c_str());
				}
			}
		}

		if (VerboseOutputEnabled() || !verbose_rules_with_parsing_errors_error_strings.empty())
		{
			std::printf("   - count of rules with parsing errors: %zu\n", verbose_rules_with_parsing_errors_error_strings.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& error_string : verbose_rules_with_parsing_errors_error_strings)
				{
					std::printf("       %ls", error_string.c_str());
				}
			}
		}

		if (VerboseOutputEnabled() || !verbose_rules_with_semantic_errors_error_strings.empty())
		{
			std::printf("   - count of rules with semantic errors: %zu\n", verbose_rules_with_semantic_errors_error_strings.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& error_string : verbose_rules_with_semantic_errors_error_strings)
				{
					std::printf("       %ls", error_string.c_str());
				}
			}
		}

		if (VerboseOutputEnabled() || !verbose_rules_with_runtime_errors_error_strings.empty())
		{
			std::printf("   - count of rules with runtime errors: %zu\n", verbose_rules_with_runtime_errors_error_strings.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& error_string : verbose_rules_with_runtime_errors_error_strings)
				{
					std::printf("       %ls", error_string.c_str());
				}
			}
		}

		if (VerboseOutputEnabled() || !verbose_rules_with_unknown_errors_error_strings.empty())
		{
			std::printf("   - count of rules with unknown errors: %zu\n", verbose_rules_with_unknown_errors_error_strings.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& error_string : verbose_rules_with_unknown_errors_error_strings)
				{
					std::printf("       %ls", error_string.c_str());
				}
			}
		}
	}
}
