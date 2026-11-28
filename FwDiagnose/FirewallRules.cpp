// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <vector>
#include <string>
#include <optional>
#include <tuple>
#include <ranges>
#include <iostream>
#include <initializer_list>
#include <type_traits>
#include <cstdint>
#include <utility>

#include <Windows.h>
#include <sddl.h>

#include "FwDiagnose.h"
#include "firewall.h"
#include "FirewallRules.h"
#include "ProfileJsonReport.h"

#include <icftypes.h>
#include <netfw.h>
#include <numeric>

#include "NormalizedFirewallRule.h"
#include "AppContainers.h"

#include "ctWmiInstance.hpp"

#include <wil/stl.h>
#include <wil/com.h>
#include <wil/resource.h>
#include <wil/registry.h>

// Shield's Up Mode
// INetFwPolicy2::get/put_BlockAllInboundTraffic
constexpr uint32_t g_minimumBannerSize = 86;

static HMODULE g_FirewallApiModule = nullptr;
static decltype(FWOpenPolicyStore)* g_FWOpenPolicyStore = nullptr;
static decltype(FWClosePolicyStore)* g_FWClosePolicyStore = nullptr;
static decltype(FWEnumFirewallRules)* g_FWEnumFirewallRules = nullptr;
static decltype(FWDeleteFirewallRule)* g_FWDeleteFirewallRule = nullptr;

static FirewallPolicyObjects g_policy_objects[] = // NOLINT(bugprone-throwing-static-initialization)
    {
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Local",
         .store_type = FW_STORE_TYPE_LOCAL},
        // { .type= FW_STORE_TYPE_DYNAMIC, .type_string= "Dynamic", .normalizedRules = {}},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Group Policy",
         .store_type = FW_STORE_TYPE_GPO},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Group Policy (RSOP)",
         .store_type = FW_STORE_TYPE_GP_RSOP},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Windows Service Hardening (Static)",
         .store_type = FW_STORE_TYPE_WSH_STATIC},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Windows Service Hardening (Configurable)",
         .store_type = FW_STORE_TYPE_WSH_CONFIGURABLE},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Interface-Isolation",
         .store_type = FW_STORE_TYPE_IF_ISO},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Interface-Isolation (Dynamic)",
         .store_type = FW_STORE_TYPE_IF_ISO_DYNAMIC},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Application-Isolation",
         .store_type = FW_STORE_TYPE_APP_ISO},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Mobile-Device-Management (MDM)",
         .store_type = FW_STORE_TYPE_MDM},
        {.parent_rule = nullptr,
         .normalizedRules = {},
         .store_type_string = "Tenant Restrictions",
         .store_type = FW_STORE_TYPE_TENANT_RESTRICTIONS},
};

// These stores deny read/write access, even to Administrators
// -clean-rules opens them read-only to report issues, but cannot delete rules from them
static bool
StoreAllowsOnlyReadAccess(FW_STORE_TYPE store_type) noexcept
{
	return store_type == FW_STORE_TYPE_MDM || store_type == FW_STORE_TYPE_GPO || store_type == FW_STORE_TYPE_GP_RSOP ||
	       store_type == FW_STORE_TYPE_WSH_STATIC || store_type == FW_STORE_TYPE_WSH_CONFIGURABLE;
}

// A store that does not exist on this system is not a failure: it simply has no rules
static bool
StoreFailedToLoad(const FirewallPolicyObjects& policy) noexcept
{
	return FAILED(policy.load_result) && policy.load_result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

static void
PrintStoreLoadFailure(const FirewallPolicyObjects& policy) noexcept
{
	std::printf(
	    "  * Could not load the rules from the %hs store (0x%lx) - it was not analyzed\n",
	    policy.store_type_string,
	    policy.load_result);
	RecordOperationFailure(policy.load_result);
}

namespace details
{
// Load the necessary functions from the FirewallAPI DLL
// as documented https://learn.microsoft.com/en-us/windows/win32/ics/firewall-functions
static void
LoadFirewallFunctions()
{
	g_FirewallApiModule = LoadLibraryW(L"FirewallAPI.dll");
	THROW_LAST_ERROR_IF(!g_FirewallApiModule);
	g_FWOpenPolicyStore = reinterpret_cast<decltype(FWOpenPolicyStore)*>(
	    GetProcAddress(g_FirewallApiModule, "FWOpenPolicyStore")); // NOLINT(clang-diagnostic-cast-function-type-strict)
	THROW_LAST_ERROR_IF_NULL(g_FWOpenPolicyStore);
	g_FWClosePolicyStore = reinterpret_cast<decltype(FWClosePolicyStore)*>(GetProcAddress(
	    g_FirewallApiModule,
	    "FWClosePolicyStore")); // NOLINT(clang-diagnostic-cast-function-type-strict)
	THROW_LAST_ERROR_IF_NULL(g_FWClosePolicyStore);
	g_FWEnumFirewallRules = reinterpret_cast<decltype(FWEnumFirewallRules)*>(GetProcAddress(
	    g_FirewallApiModule,
	    "FWEnumFirewallRules")); // NOLINT(clang-diagnostic-cast-function-type-strict)
	THROW_LAST_ERROR_IF_NULL(g_FWEnumFirewallRules);
	g_FWDeleteFirewallRule = reinterpret_cast<decltype(FWDeleteFirewallRule)*>(GetProcAddress(
	    g_FirewallApiModule,
	    "FWDeleteFirewallRule")); // NOLINT(clang-diagnostic-cast-function-type-strict)
	THROW_LAST_ERROR_IF_NULL(g_FWDeleteFirewallRule);
}

static HRESULT
LoadFirewallRulesFromStore(FirewallPolicyObjects& policy)
{
	ChronoTimer timer;

	const auto store_access_right = CleanBrokenRulesEnabled() && !StoreAllowsOnlyReadAccess(policy.store_type)
	                                    ? FW_POLICY_ACCESS_RIGHT_READ_WRITE
	                                    : FW_POLICY_ACCESS_RIGHT_READ;

	// try all supported versions of the Firewall API - from most recent to oldest supported
	DWORD openStoreError{};
	WORD versionSelected{};
	for (const auto version : {FW_BINARY_VERSION_33, FW_BINARY_VERSION_31, FW_BINARY_VERSION_27})
	{
		versionSelected = version;
		timer.start("OpenPolicyStore");
		openStoreError = g_FWOpenPolicyStore(
		    versionSelected,
		    nullptr,
		    policy.store_type,
		    store_access_right,
		    FW_POLICY_STORE_FLAGS_NONE,
		    &policy.store_handle);
		if (openStoreError == ERROR_SUCCESS)
		{
			// succeeded in opening the store
			break;
		}

		if (openStoreError != ERROR_SUCCESS)
		{
			if (openStoreError == ERROR_ACCESS_DENIED)
			{
				// every store can be denied for the same reason, so only print this once
				static bool printed_elevation_message = false;
				if (!printed_elevation_message)
				{
					printed_elevation_message = true;
					std::printf(
					    "\n  Administrative privileges required - try running from an elevated Administrator "
					    "command prompt\n");
				}
				return HRESULT_FROM_WIN32(openStoreError);
			}

			if (openStoreError == ERROR_FILE_NOT_FOUND)
			{
				// std::printf("\n  The %s Firewall Policy Store does not exist on this system.", policy.type_string);
				// this succeeded in opening the store (version is supported), but it does not exist on this system
				return HRESULT_FROM_WIN32(openStoreError);
			}
		}
		timer.end();
	}
	if (openStoreError != ERROR_SUCCESS)
	{
		std::printf(
		    "  Failed to open %s firewall policy store. Error: 0x%lx\n",
		    policy.store_type_string,
		    HRESULT_FROM_WIN32(openStoreError));
		return HRESULT_FROM_WIN32(openStoreError);
	}

	timer.start("EnumFirewallRules");
	DWORD num_rules = 0;
	const auto enumRulesError = g_FWEnumFirewallRules(
	    policy.store_handle,
	    static_cast<DWORD>(FW_RULE_STATUS_CLASS_ALL),
	    FW_PROFILE_TYPE_ALL,
	    FW_ENUM_RULES_FLAG_INCLUDE_METADATA | FW_ENUM_RULES_FLAG_RESOLVE_NAME | FW_ENUM_RULES_FLAG_RESOLVE_DESCRIPTION,
	    &num_rules,
	    &policy.parent_rule);
	if (enumRulesError != ERROR_SUCCESS)
	{
		std::printf("  Failed to enumerate firewall rules. Error: 0x%lx\n", HRESULT_FROM_WIN32(enumRulesError));
		THROW_WIN32(enumRulesError);
	}
	timer.end();

	// cannot FWFreeFirewallRules - we keep those pointers around to read later

	timer.start("Normalizing Firewall rules into a vector");
	FW_RULE* rule_iterator = policy.parent_rule;
	while (rule_iterator)
	{
		policy.normalizedRules.emplace_back(rule_iterator, versionSelected);
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
			    return RuleDetailsComparison(lhs, rhs, comparison_policy_compare_all) < 0;
		    });
		timer.end();
		if (VerboseOutputEnabled())
		{
			std::printf("\n");
		}
	}

	return S_OK;
}

//
// RankRulesByFilterCounts
//
// Ranks one store's rule names by WFP filter and filter-condition counts, writes the rankings
// to the JSON report, and prints them. Records a failure for the exit code when the WFP filters
// could not be read.
//
// Parameters:
//   policy [in] - the store whose rules are ranked; LoadWfpFilters must already have run
//
static void
RankRulesByFilterCounts(const FirewallPolicyObjects& policy)
{
	// the only link from filters to rules is the display name
	SortFilterDetailsByName();
	const auto rankings = AnalyzeFilterRankings(
	    policy.normalizedRules,
	    WfpFiltersLoadResult(),
	    VerboseOutputEnabled() ? AnalysisOutput::Verbose : AnalysisOutput::Summary,
	    [](const NormalizedString& rule_name)
	    {
		    return FilterCounts{CountFiltersByName(rule_name), CountFilterConditionsByName(rule_name)};
	    });
	if (FAILED(rankings.filtersLoadResult))
	{
		RecordOperationFailure(rankings.filtersLoadResult);
	}

	WriteFilterRankingsJson(policy, rankings, CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules");
	std::printf("%ls", PrintFilterRankings(rankings).c_str());
}

namespace
{
enum class InboundProfileCategory : uint8_t
{
	PrivateProfileOnly,
	IncludesDomainProfile,
	IncludesPublicProfile
};

struct InboundRuleGroup
{
	std::vector<const NormalizedFirewallRule*> service_rules;
	std::vector<const NormalizedFirewallRule*> system_rules;
	std::vector<const NormalizedFirewallRule*> application_rules;
	std::vector<const NormalizedFirewallRule*> non_application_or_service_rules;

	size_t allow_rule_count{};
	size_t allow_bypass_rule_count{};
	size_t block_rule_count{};
	size_t enabled_rule_count{};
	size_t disabled_rule_count{};
	size_t rules_targeting_users{};

	// count of rules that were move from a private or domain InboundRuleGroup
	// to the Public InboundRuleGroup because the rules matched a rule from the Public profile
	size_t count_moved_matching_local_subnet{};

	size_t
	rule_count() const
	{
		WI_ASSERT(
		    enabled_rule_count + disabled_rule_count == service_rules.size() + system_rules.size() +
		                                                    application_rules.size() +
		                                                    non_application_or_service_rules.size());
		WI_ASSERT(enabled_rule_count + disabled_rule_count == allow_rule_count + allow_bypass_rule_count);
		return enabled_rule_count + disabled_rule_count;
	}

	void
	add_rule(const NormalizedFirewallRule& rule_details)
	{
		if (rule_details.fw_rule->Action == FW_RULE_ACTION_ALLOW_BYPASS)
		{
			++allow_bypass_rule_count;
		}
		else if (rule_details.fw_rule->Action == FW_RULE_ACTION_BLOCK)
		{
			++block_rule_count;
		}
		else
		{
			WI_ASSERT(rule_details.fw_rule->Action == FW_RULE_ACTION_ALLOW);
			++allow_rule_count;
		}

		if (rule_details.is_rule_enabled)
		{
			++enabled_rule_count;
		}
		else
		{
			++disabled_rule_count;
		}

		if (rule_details.RuleTargetsLocalUser())
		{
			++rules_targeting_users;
		}

		if (rule_details.RuleTargetsNtService())
		{
			service_rules.push_back(&rule_details);
		}
		else if (rule_details.RuleTargetsLocalSystemApplication())
		{
			system_rules.push_back(&rule_details);
		}
		else if (rule_details.RuleTargetsLocalNonSystemApplication())
		{
			application_rules.push_back(&rule_details);
		}
		else
		{
			non_application_or_service_rules.push_back(&rule_details);
		}
	}

	// swap the counts of lhs into rhs
	static void
	swap_rule_counts(const NormalizedFirewallRule& lhs_rule_details, InboundRuleGroup& lhs, InboundRuleGroup& rhs)
	{
		switch (lhs_rule_details.fw_rule->Action)
		{
		case FW_RULE_ACTION_ALLOW_BYPASS:
			--lhs.allow_bypass_rule_count;
			++rhs.allow_bypass_rule_count;
			break;

		case FW_RULE_ACTION_BLOCK:
			--lhs.block_rule_count;
			++rhs.block_rule_count;
			break;

		default:
			if (lhs_rule_details.fw_rule->Action != FW_RULE_ACTION_ALLOW)
			{
				// this should never happen, but if it does, count it as an allow rule
				// this is consistent with how add_rule() counts any other action as an allow rule
				std::printf(
				    "  ** Unexpected firewall rule Action - counting it as an allow rule. Rule details:\n%ls\n",
				    lhs_rule_details.PrintRule().c_str());
			}

			// add_rule counts any other action as an allow rule, so these counts must stay consistent with it
			--lhs.allow_rule_count;
			++rhs.allow_rule_count;
			break;
		}

		if (lhs_rule_details.is_rule_enabled)
		{
			--lhs.enabled_rule_count;
			++rhs.enabled_rule_count;
		}
		else
		{
			--lhs.disabled_rule_count;
			++rhs.disabled_rule_count;
		}

		if (lhs_rule_details.RuleTargetsLocalUser())
		{
			--lhs.rules_targeting_users;
			++rhs.rules_targeting_users;
		}
	}
};

struct InboundRuleAnalysis
{
	InboundRuleGroup private_only;
	// includes_domain_profile does not include any rules that also include the public profile
	InboundRuleGroup includes_domain_profile;
	InboundRuleGroup includes_public_profile;
	InboundRuleGroup duplicate_of_public_profile;
};
} // namespace

static bool
IsInboundAllowRule(const NormalizedFirewallRule& rule_details) noexcept
{
	return rule_details.fw_rule->Direction == FW_DIR_IN &&
	       (rule_details.fw_rule->Action == FW_RULE_ACTION_ALLOW ||
	        rule_details.fw_rule->Action == FW_RULE_ACTION_ALLOW_BYPASS);
}

static InboundProfileCategory
GetInboundProfileCategory(const NormalizedFirewallRule& rule_details) noexcept
{
	// if it includes the public profile with any other combination, it is considered to be a public profile rule
	if (rule_details.fw_rule->dwProfiles & FW_PROFILE_TYPE_PUBLIC)
	{
		return InboundProfileCategory::IncludesPublicProfile;
	}

	if (rule_details.fw_rule->dwProfiles == FW_PROFILE_TYPE_PRIVATE)
	{
		return InboundProfileCategory::PrivateProfileOnly;
	}

	WI_ASSERT(rule_details.fw_rule->dwProfiles & FW_PROFILE_TYPE_DOMAIN);
	return InboundProfileCategory::IncludesDomainProfile;
}

static InboundRuleAnalysis
AnalyzeInboundRules(const std::vector<NormalizedFirewallRule>& normalized_rules)
{
	InboundRuleAnalysis analysis;

	for (const auto& rule_details : normalized_rules)
	{
		if (IsInboundAllowRule(rule_details))
		{
			switch (GetInboundProfileCategory(rule_details))
			{
			case InboundProfileCategory::PrivateProfileOnly:
				analysis.private_only.add_rule(rule_details);
				break;
			case InboundProfileCategory::IncludesDomainProfile:
				analysis.includes_domain_profile.add_rule(rule_details);
				break;
			case InboundProfileCategory::IncludesPublicProfile:
				analysis.includes_public_profile.add_rule(rule_details);
				break;
			default:
				FAIL_FAST();
			}
		}
	}

	// check if a private-only or a domain-rule is a copy of a public rule (using the public_policy_comparison_policy)
	// if it is, then move it to the duplicate_of_public_profile group, as it's not really a private-only rule
	// returns how many rules were
	const auto UpdateRuleGroupIfMatchesPublicRules =
	    [&](InboundRuleGroup& lhs_rule_group, ComparisonPolicy comparison_policy)
	{
		// will erase from the private-only vector, which will invalidate the iterators, so we cannot update the iterator here in the for statement
		// the iterator will be updated in the loop body either from calling erase() or from incrementing it if we don't erase
		for (auto lhs_rule_iterator = lhs_rule_group.service_rules.begin();
		     lhs_rule_iterator != lhs_rule_group.service_rules.end();)
		{
			const auto lhs_rule = *lhs_rule_iterator;

			bool lhs_iterator_invalidated = false;
			for (const auto& public_rule : analysis.includes_public_profile.service_rules)
			{
				if (RuleDetailsComparison(*lhs_rule, *public_rule, comparison_policy) == 0)
				{
					const auto keywords_comparison = CompareKeywords(lhs_rule->fw_rule, public_rule->fw_rule);
					const auto keywords_comparison_minus_local_subnet =
					    CompareKeywordsIgnoringLocalSubnet(lhs_rule->fw_rule, public_rule->fw_rule);
					if (keywords_comparison != keywords_comparison_minus_local_subnet)
					{
						// the rules matched, but the keywords didn't match once we didn't consider local subnet
						std::printf("\n <<-->>\n");
						++analysis.duplicate_of_public_profile.count_moved_matching_local_subnet;
					}

					// move the private-only rule to public, as it's not really private-only
					// decrement/increment the counts in each group
					InboundRuleGroup::swap_rule_counts(*lhs_rule, lhs_rule_group, analysis.duplicate_of_public_profile);

					// move the rule from the private to the duplicate_of_public_profile group
					analysis.duplicate_of_public_profile.service_rules.emplace_back(lhs_rule);

					lhs_rule_iterator = lhs_rule_group.service_rules.erase(lhs_rule_iterator);
					lhs_iterator_invalidated = true;

					break;
				}
			}

			if (!lhs_iterator_invalidated)
			{
				++lhs_rule_iterator;
			}
		}

		// will erase from the private-only vector, which will invalidate the iterators, so we cannot update the iterator here in the for statement
		// the iterator will be updated in the loop body either from calling erase() or from incrementing it if we don't erase
		for (auto lhs_rule_iterator = lhs_rule_group.system_rules.begin();
		     lhs_rule_iterator != lhs_rule_group.system_rules.end();)
		{
			const auto lhs_rule = *lhs_rule_iterator;

			bool lhs_iterator_invalidated = false;
			for (const auto& public_rule : analysis.includes_public_profile.system_rules)
			{
				if (RuleDetailsComparison(*lhs_rule, *public_rule, comparison_policy) == 0)
				{
					const auto keywords_comparison = CompareKeywords(lhs_rule->fw_rule, public_rule->fw_rule);
					const auto keywords_comparison_minus_local_subnet =
					    CompareKeywordsIgnoringLocalSubnet(lhs_rule->fw_rule, public_rule->fw_rule);
					if (keywords_comparison != keywords_comparison_minus_local_subnet)
					{
						// the rules matched, but the keywords didn't match once we didn't consider local subnet
						++analysis.duplicate_of_public_profile.count_moved_matching_local_subnet;
					}

					// move the private-only rule to duplicate_of_public_profile, as it's not really private-only
					// decrement/increment the counts in each group
					InboundRuleGroup::swap_rule_counts(*lhs_rule, lhs_rule_group, analysis.duplicate_of_public_profile);

					// move the rule from the private to the duplicate_of_public_profile group
					analysis.duplicate_of_public_profile.system_rules.emplace_back(lhs_rule);

					lhs_rule_iterator = lhs_rule_group.system_rules.erase(lhs_rule_iterator);
					lhs_iterator_invalidated = true;

					break;
				}
			}

			if (!lhs_iterator_invalidated)
			{
				++lhs_rule_iterator;
			}
		}

		for (auto lhs_rule_iterator = lhs_rule_group.application_rules.begin();
		     lhs_rule_iterator != lhs_rule_group.application_rules.end();)
		{
			const auto lhs_rule = *lhs_rule_iterator;

			bool lhs_iterator_invalidated = false;
			for (const auto& public_rule : analysis.includes_public_profile.application_rules)
			{
				if (RuleDetailsComparison(*lhs_rule, *public_rule, comparison_policy) == 0)
				{
					const auto keywords_comparison = CompareKeywords(lhs_rule->fw_rule, public_rule->fw_rule);
					const auto keywords_comparison_minus_local_subnet =
					    CompareKeywordsIgnoringLocalSubnet(lhs_rule->fw_rule, public_rule->fw_rule);
					if (keywords_comparison != keywords_comparison_minus_local_subnet)
					{
						// the rules matched, but the keywords didn't match once we didn't consider local subnet
						std::printf("\n <<-->>\n");
						++analysis.duplicate_of_public_profile.count_moved_matching_local_subnet;
					}

					// move the private-only rule to duplicate_of_public_profile, as it's not really private-only
					// decrement/increment the counts in each group
					InboundRuleGroup::swap_rule_counts(*lhs_rule, lhs_rule_group, analysis.duplicate_of_public_profile);

					// move the rule from the private to the duplicate_of_public_profile group
					analysis.duplicate_of_public_profile.application_rules.emplace_back(lhs_rule);

					lhs_rule_iterator = lhs_rule_group.application_rules.erase(lhs_rule_iterator);
					lhs_iterator_invalidated = true;

					break;
				}
			}

			if (!lhs_iterator_invalidated)
			{
				++lhs_rule_iterator;
			}
		}

		for (auto lhs_rule_iterator = lhs_rule_group.non_application_or_service_rules.begin();
		     lhs_rule_iterator != lhs_rule_group.non_application_or_service_rules.end();)
		{
			const auto lhs_rule = *lhs_rule_iterator;

			bool lhs_iterator_invalidated = false;
			for (const auto& public_rule : analysis.includes_public_profile.non_application_or_service_rules)
			{
				if (RuleDetailsComparison(*lhs_rule, *public_rule, comparison_policy) == 0)
				{
					const auto keywords_comparison = CompareKeywords(lhs_rule->fw_rule, public_rule->fw_rule);
					const auto keywords_comparison_minus_local_subnet =
					    CompareKeywordsIgnoringLocalSubnet(lhs_rule->fw_rule, public_rule->fw_rule);
					if (keywords_comparison != keywords_comparison_minus_local_subnet)
					{
						// the rules matched, but the keywords didn't match once we didn't consider local subnet
						std::printf("\n <<-->>\n");
						++analysis.duplicate_of_public_profile.count_moved_matching_local_subnet;
					}

					// move the private-only rule to duplicate_of_public_profile, as it's not really private-only
					// decrement/increment the counts in each group
					InboundRuleGroup::swap_rule_counts(*lhs_rule, lhs_rule_group, analysis.duplicate_of_public_profile);

					// move the rule from the private to the duplicate_of_public_profile group
					analysis.duplicate_of_public_profile.non_application_or_service_rules.emplace_back(lhs_rule);

					lhs_rule_iterator = lhs_rule_group.non_application_or_service_rules.erase(lhs_rule_iterator);
					lhs_iterator_invalidated = true;

					break;
				}
			}

			if (!lhs_iterator_invalidated)
			{
				++lhs_rule_iterator;
			}
		}
	};

	static constexpr auto private_profile_comparison_policy_including_local_subnet =
	    comparison_policy_skip_comparing_if_enabled | comparison_policy_skip_comparing_profiles |
	    comparison_policy_skip_comparing_local_subnet;
	UpdateRuleGroupIfMatchesPublicRules(
	    analysis.private_only,
	    private_profile_comparison_policy_including_local_subnet);

	static constexpr auto domain_profile_comparison_policy =
	    comparison_policy_skip_comparing_if_enabled | comparison_policy_skip_comparing_profiles;
	UpdateRuleGroupIfMatchesPublicRules(analysis.includes_domain_profile, domain_profile_comparison_policy);
	return analysis;
}

static void
PrintVerboseInboundRules(PCSTR heading, const std::vector<const NormalizedFirewallRule*>& rules)
{
	if (!VerboseOutputEnabled() || rules.empty())
	{
		return;
	}

	std::printf("    %s:\n", heading);
	size_t counter = 0;
	for (const auto* rule_details : rules)
	{
		++counter;
		std::printf("%ws", PrintRuleContents(*rule_details, counter).c_str());
		std::printf(
		    "           Action: %s%s\n",
		    rule_details->fw_rule->Action == FW_RULE_ACTION_ALLOW_BYPASS ? "Allow bypass" : "Allow",
		    rule_details->fw_rule->Action == FW_RULE_ACTION_ALLOW_BYPASS
		        ? " (takes precedence over matching block rules)"
		        : " (matching block rules take precedence)");
		std::printf("           Status: %s\n", rule_details->is_rule_enabled ? "Enabled" : "Disabled");
	}
}

static void
PrintInboundRuleGroup(PCSTR heading, const InboundRuleGroup& group)
{
	if (group.rule_count() == 0)
	{
		return;
	}
	std::printf("\n%s inbound allow rules: %zu\n", heading, group.rule_count());
	std::printf("  Enabled rule count: %zu\n", group.enabled_rule_count);
	std::printf("  Disabled rule count: %zu\n", group.disabled_rule_count);
	std::printf("  Block rule count: %zu\n", group.block_rule_count);
	std::printf("  Allow rule count: %zu\n", group.allow_rule_count);
	if (group.allow_bypass_rule_count > 0)
	{
		std::printf(
		    "  Allow-bypass rule count: %zu (takes precedence over matching block rules)\n",
		    group.allow_bypass_rule_count);
	}
	std::printf("   - Targeting specific applications: %zu\n", group.application_rules.size());
	std::printf("   - Targeting System (drivers): %zu\n", group.system_rules.size());
	std::printf("   - Targeting an NT Service: %zu\n", group.service_rules.size());
	if (group.non_application_or_service_rules.size() > 0)
	{
		std::printf(
		    "   - Targeting neither an application nor an NT Service: %zu\n",
		    group.non_application_or_service_rules.size());
	}
	if (group.rules_targeting_users > 0)
	{
		std::printf("   - Targeting an individual user: %zu\n", group.rules_targeting_users);
	}

	PrintVerboseInboundRules("Rules targeting specific applications", group.application_rules);
	PrintVerboseInboundRules("Rules targeting System (drivers)", group.system_rules);
	PrintVerboseInboundRules("Rules targeting an NT Service", group.service_rules);
	PrintVerboseInboundRules("Rules not targeting an application or service", group.non_application_or_service_rules);
}

static void
PrintInboundRuleAnalysis(const InboundRuleAnalysis& inbound_rule_analysis)
{
	std::printf("\nAnalysis if Firewall rules allowing inbound connectivity\n");
	size_t total_rule_count = inbound_rule_analysis.private_only.rule_count() +
	                          inbound_rule_analysis.includes_domain_profile.rule_count() +
	                          inbound_rule_analysis.includes_public_profile.rule_count() +
	                          inbound_rule_analysis.duplicate_of_public_profile.rule_count();

	if (total_rule_count > 0)
	{
		// clang-format off
		std::printf("Note that if a Private or Domain rule matches a Public rules, it's counted as Public\n");
		std::printf("- This is because if the rules are equivalent, they would be allowed on the Public profile\n");
		std::printf("- When considering equivalency, Private profile comparisons do not consider the Matching-Subnet keyword\n");
		std::printf("  (the security profile is not significantly different on-network or routed with > 1 hops in today's deployments)\n");
		std::printf("\n");
		// clang-format on
	}

	std::printf("Total Firewall rules allowing inbound connectivity: %zu\n", total_rule_count);
	if (total_rule_count == 0)
	{
		return;
	}

	std::printf("  Private profile only: %zu\n", inbound_rule_analysis.private_only.rule_count());
	std::printf(
	    "  Domain profile (exclusive of the Public profile): %zu\n",
	    inbound_rule_analysis.includes_domain_profile.rule_count());
	std::printf(
	    "  Public profiles (in combination with any other profile): %zu\n",
	    inbound_rule_analysis.includes_public_profile.rule_count());
	std::printf(
	    "  Private or Domain rules that matched a Public rule (thus not considered exclusively Private or Domain): "
	    "%zu\n",
	    inbound_rule_analysis.duplicate_of_public_profile.rule_count());
	if (inbound_rule_analysis.duplicate_of_public_profile.count_moved_matching_local_subnet > 0)
	{
		std::printf(
		    "   - Private rules matching a Public rules - differing by specifying the remote address is Local Subnet "
		    "or not: %zu\n",
		    inbound_rule_analysis.duplicate_of_public_profile.count_moved_matching_local_subnet);
	}

	PrintInboundRuleGroup("Private profile only", inbound_rule_analysis.private_only);
	PrintInboundRuleGroup(
	    "Domain profile (exclusive of the Public profile)",
	    inbound_rule_analysis.includes_domain_profile);
	PrintInboundRuleGroup(
	    "Public profiles (in combination with any other profile)",
	    inbound_rule_analysis.includes_public_profile);
	PrintInboundRuleGroup(
	    "Private or Domain rules that matched a Public rule (thus not considered exclusively Private or Domain)",
	    inbound_rule_analysis.duplicate_of_public_profile);
}

//
// CheckForDuplicateRules
//
// Finds one store's sets of duplicate rules, writes them to the JSON report, and prints them.
//
// Parameters:
//   policy  [in, out] - the store whose rules are checked; its rules are reordered so each set is adjacent
//   command [in]      - the JSON command the store record belongs to, e.g. L"analyze_rules"
//
// Returns:
//   The sets of duplicate rules, which refer into policy.normalizedRules; DeleteDuplicateRules
//   deletes all but one rule of each set.
//
static DuplicateAnalysis
CheckForDuplicateRules(FirewallPolicyObjects& policy, PCWSTR command)
{
	auto analysis = AnalyzeDuplicateRules(policy.normalizedRules);
	WriteDuplicateAnalysisJson(policy, analysis, command);
	std::printf(
	    "%ls",
	    PrintDuplicateAnalysis(analysis, VerboseOutputEnabled() ? AnalysisOutput::Verbose : AnalysisOutput::Summary)
	        .c_str());
	return analysis;
}

static void
CheckForMissingAppRules(const FirewallPolicyObjects& policy)
{
	const auto analysis = AnalyzeApplicationRules(
	    policy.normalizedRules,
	    RunningUnderWow64() ? ApplicationFileCheck::SkippedWow64Redirection : ApplicationFileCheck::Completed);
	WriteApplicationAnalysisJson(policy, analysis, CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules");
	std::printf(
	    "%ls",
	    PrintApplicationAnalysis(analysis, VerboseOutputEnabled() ? AnalysisOutput::Verbose : AnalysisOutput::Summary)
	        .c_str());
}

static void
CheckForMissingAppPackage(FirewallPolicyObjects& policy)
{
	const PackageLookups lookups{
	    [](PCWSTR package_sid)
	    {
		    return std::get<1>(FindPackageSid(package_sid)) != AppContainerName::None;
	    },
	    [](const NormalizedString& package_family_name)
	    {
		    return std::get<1>(FindPackageFamilyName(package_family_name)) != AppContainerName::None;
	    }};
	const auto analysis = AnalyzePackageRules(policy.normalizedRules, GetAppPackagesLoadResult(), lookups);
	if (FAILED(analysis.packagesLoadResult))
	{
		RecordOperationFailure(analysis.packagesLoadResult);
	}

	WritePackageAnalysisJson(policy, analysis, CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules");
	std::printf(
	    "%ls",
	    PrintPackageAnalysis(analysis, VerboseOutputEnabled() ? AnalysisOutput::Verbose : AnalysisOutput::Summary)
	        .c_str());
}

static void
CheckUnresolvedUserAccountRules(FirewallPolicyObjects& policy)
{
	const bool check_for_local_profile =
	    policy.store_type == FW_STORE_TYPE_APP_ISO || policy.store_type == FW_STORE_TYPE_IF_ISO;

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
			if (VerboseOutputEnabled())
			{
				std::printf("Failed to ConvertStringSidToSid(%ls) (0x%lx)\n", sid_string, HRESULT_FROM_WIN32(gle));
			}
			return std::nullopt;
		}

		DWORD localUserOwnerNameSize = 0;
		DWORD cchReferencedDomainName = 0;
		SID_NAME_USE sid_name_use = SidTypeUser;
		if (!LookupAccountSidW(
		        nullptr,
		        localUserOwnerSid.get(),
		        localUserOwnerName.data(),
		        &localUserOwnerNameSize,
		        localUserDomainName.data(),
		        &cchReferencedDomainName,
		        &sid_name_use))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				localUserOwnerName.resize(localUserOwnerNameSize);
				localUserDomainName.resize(cchReferencedDomainName);

				if (!LookupAccountSidW(
				        nullptr,
				        localUserOwnerSid.get(),
				        localUserOwnerName.data(),
				        &localUserOwnerNameSize,
				        localUserDomainName.data(),
				        &cchReferencedDomainName,
				        &sid_name_use))
				{
					const auto gle = GetLastError();
					if (DebugOutputEnabled())
					{
						std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", sid_string, HRESULT_FROM_WIN32(gle));
					}
					return std::nullopt;
				}

				// on success, the sizes exclude the null terminator that the first call included
				localUserOwnerName.resize(localUserOwnerNameSize);
				localUserDomainName.resize(cchReferencedDomainName);

				if (DebugOutputEnabled())
				{
					if (localUserDomainName.empty())
					{
						std::printf(
						    "Successfully converted LocalUserOwner SID %ls to %ls\n",
						    sid_string,
						    localUserOwnerName.c_str());
					}
					else
					{
						std::printf(
						    "Successfully converted LocalUserOwner SID %ls to %ls\\%ls\n",
						    sid_string,
						    localUserDomainName.c_str(),
						    localUserOwnerName.c_str());
					}
				}
			}
			else
			{
				const auto gle = GetLastError();
				if (DebugOutputEnabled())
				{
					std::printf("Failed to LookupAccountSid(%ls) (0x%lx)\n", sid_string, HRESULT_FROM_WIN32(gle));
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

	LocalProfiles local_profiles;
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

		if (DebugOutputEnabled())
		{
			std::printf("  * Querying local user profiles from the registry...\n");
		}

		try
		{
			const auto profile_key = wil::reg::open_unique_key(
			    HKEY_LOCAL_MACHINE,
			    LR"(Software\Microsoft\Windows NT\CurrentVersion\ProfileList)");
			for (const auto& key_data :
			     wil::make_range(wil::reg::key_iterator{profile_key.get()}, wil::reg::key_iterator{}))
			{
				auto profile_sid = key_data.name;
				const auto optional_name_conversion = convert_sid_to_name(profile_sid.c_str());
				if (optional_name_conversion.has_value())
				{
					const auto& [domain_name, user_name] = optional_name_conversion.value();
					if (DebugOutputEnabled())
					{
						std::printf(
						    "    Local profile SID: %ls  (%ls\\%ls)\n",
						    profile_sid.c_str(),
						    domain_name.c_str(),
						    user_name.c_str());
					}
					local_profiles.sids.emplace_back(std::move(profile_sid));
				}
				else
				{
					if (DebugOutputEnabled())
					{
						std::printf("    Local profile SID: %ls  (Failed to resolve the SID)\n", profile_sid.c_str());
					}
				}
			}
			local_profiles.check = LocalProfileCheck::Completed;
		}
		catch (...)
		{
			// without the profile list, every owner would look like it has no local profile
			local_profiles.check = LocalProfileCheck::Failed;
			local_profiles.readResult = wil::ResultFromCaughtException();
			local_profiles.sids.clear();
			RecordOperationFailure(local_profiles.readResult);
		}

		if (DebugOutputEnabled())
		{
			std::printf("\n");
		}
	}

	const auto analysis = AnalyzeUserOwnerRules(policy.normalizedRules, local_profiles);
	if (DebugOutputEnabled())
	{
		for (const auto& rule : policy.normalizedRules)
		{
			if (rule.successfully_resolved_user_name_with_local_profile.value_or(false))
			{
				std::printf(
				    "    Rule with a SID matching a local profile:  '%ls' (%ls\\%ls)\n"
				    "      [%ls:  %ls]\n",
				    rule.fw_rule->wszLocalUserOwner,
				    rule.local_user_domain_name.c_str(),
				    rule.local_user_owner_name.c_str(),
				    rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
				    rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str());
			}
		}
	}

	WriteUserOwnerAnalysisJson(policy, analysis, CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules");
	std::printf(
	    "%ls",
	    PrintUserOwnerAnalysis(analysis, VerboseOutputEnabled() ? AnalysisOutput::Verbose : AnalysisOutput::Summary)
	        .c_str());
}

//
// SortRulesByName
//
// Sorts rules alphabetically by name, ignoring case, the order the later analyses report them in.
//
// Parameters:
//   normalized_rules [in, out] - the store's rules, sorted in place
//
static void
SortRulesByName(std::vector<NormalizedFirewallRule>& normalized_rules)
{
	// the analyses that follow report rules in name order
	std::ranges::sort(
	    normalized_rules,
	    [](const NormalizedFirewallRule& lhs, const NormalizedFirewallRule& rhs) noexcept
	    {
		    return NormalizedString::AlphabeticalCompare(lhs.rule_name, rhs.rule_name) < 0;
	    });
}

static void
CheckForRulesWithErrorStatus(const FirewallPolicyObjects& policy)
{
	const auto& normalized_rules = policy.normalizedRules;
	size_t rules_with_no_errors = 0;
	RuleStatusCategories status_categories;

	std::vector<std::wstring> verbose_rules_partially_ignored_error_strings;
	std::vector<std::wstring> verbose_rules_completely_ignored_error_strings;
	std::vector<std::wstring> verbose_rules_with_parsing_errors_error_strings;
	std::vector<std::wstring> verbose_rules_with_semantic_errors_error_strings;
	std::vector<std::wstring> verbose_rules_with_runtime_errors_error_strings;
	std::vector<std::wstring> verbose_rules_with_unknown_errors_error_strings;

	for (const auto& rule : normalized_rules)
	{
		if ((rule.fw_rule->Status & FW_RULE_STATUS_OK) == FW_RULE_STATUS_OK)
		{
			++rules_with_no_errors;
		}
		else if ((rule.fw_rule->Status & FW_RULE_STATUS_PARTIALLY_IGNORED) == FW_RULE_STATUS_PARTIALLY_IGNORED)
		{
			status_categories.partiallyIgnored.rules.push_back(&rule);
			verbose_rules_partially_ignored_error_strings.emplace_back(
			    wil::str_printf<std::wstring>(
			        L"A rule has some fields that were not understood and ignored:  %ls:  %ls\n",
			        rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			        rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str()));
		}
		else if ((rule.fw_rule->Status & FW_RULE_STATUS_IGNORED) == FW_RULE_STATUS_IGNORED)
		{
			status_categories.ignored.rules.push_back(&rule);
			verbose_rules_completely_ignored_error_strings.emplace_back(
			    wil::str_printf<std::wstring>(
			        L"A rule was completely ignored:  %ls:  %ls\n",
			        rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			        rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str()));
		}
		else if ((rule.fw_rule->Status & FW_RULE_STATUS_PARSING_ERROR) == FW_RULE_STATUS_PARSING_ERROR)
		{
			status_categories.parsingError.rules.push_back(&rule);
			verbose_rules_with_parsing_errors_error_strings.emplace_back(
			    wil::str_printf<std::wstring>(
			        L"A rule has parsing error (0x%08X):  %ls:  %ls\n",
			        rule.fw_rule->Status,
			        rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			        rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str()));
		}
		else if ((rule.fw_rule->Status & FW_RULE_STATUS_SEMANTIC_ERROR) == FW_RULE_STATUS_SEMANTIC_ERROR)
		{
			status_categories.semanticError.rules.push_back(&rule);
			verbose_rules_with_semantic_errors_error_strings.emplace_back(
			    wil::str_printf<std::wstring>(
			        L"A rule has semantic error (0x%08X):  %ls:  %ls\n",
			        rule.fw_rule->Status,
			        rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			        rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str()));
		}
		else if ((rule.fw_rule->Status & FW_RULE_STATUS_RUNTIME_ERROR) == FW_RULE_STATUS_RUNTIME_ERROR)
		{
			status_categories.runtimeError.rules.push_back(&rule);
			verbose_rules_with_runtime_errors_error_strings.emplace_back(
			    wil::str_printf<std::wstring>(
			        L"A rule has runtime error (0x%08X):  %ls:  %ls\n",
			        rule.fw_rule->Status,
			        rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			        rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str()));
		}
		else
		{
			status_categories.unknown.rules.push_back(&rule);
			verbose_rules_with_unknown_errors_error_strings.emplace_back(
			    wil::str_printf<std::wstring>(
			        L"    A rule has unknown error status (0x%08X):  %ls:  %ls\n",
			        rule.fw_rule->Status,
			        rule.rule_name.value.empty() ? L"(no Rule Name) RuleId" : L"Rule Name",
			        rule.rule_name.value.empty() ? rule.fw_rule->wszRuleId : rule.rule_name.value.c_str()));
		}
	}

	WriteFirewallRuleStatusJson(
	    policy,
	    rules_with_no_errors,
	    status_categories,
	    CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules",
	    RuleStatusAnalysis::Performed);

	if (!normalized_rules.empty())
	{
		std::printf("  * Summary of status analysis of firewall rules:\n");
		std::printf(
		    "   - count of rules with no errors: %zu (out of a total of %zu rules)\n",
		    rules_with_no_errors,
		    normalized_rules.size());

		if (VerboseOutputEnabled() || !verbose_rules_partially_ignored_error_strings.empty())
		{
			std::printf(
			    "   - count of rules with partially ignored (some fields not understood): %zu\n",
			    verbose_rules_partially_ignored_error_strings.size());
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
			std::printf(
			    "   - count of rules with completely ignored (newer schema with unknown fields): %zu\n",
			    verbose_rules_completely_ignored_error_strings.size());
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
			std::printf(
			    "   - count of rules with parsing errors: %zu\n",
			    verbose_rules_with_parsing_errors_error_strings.size());
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
			std::printf(
			    "   - count of rules with semantic errors: %zu\n",
			    verbose_rules_with_semantic_errors_error_strings.size());
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
			std::printf(
			    "   - count of rules with runtime errors: %zu\n",
			    verbose_rules_with_runtime_errors_error_strings.size());
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
			std::printf(
			    "   - count of rules with unknown errors: %zu\n",
			    verbose_rules_with_unknown_errors_error_strings.size());
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
} // namespace details

bool
HasFirewallAdminAccess()
{
	ChronoTimer timer;
	FW_POLICY_STORE_HANDLE test_handle = nullptr;

	timer.start("OpenPolicyStore");
	const auto openStoreError = g_FWOpenPolicyStore(
	    FW_BINARY_VERSION_27, // the earliest version supported - just testing for access
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

HRESULT
LoadFirewallRules() noexcept
try
{
	details::LoadFirewallFunctions();

	// a failure in one store must not prevent loading the others: each store records its own result
	HRESULT first_failure = S_OK;
	for (auto& policy : g_policy_objects)
	{
		try
		{
			policy.load_result = details::LoadFirewallRulesFromStore(policy);
		}
		catch (...)
		{
			policy.load_result = wil::ResultFromCaughtException();
		}

		if (SUCCEEDED(first_failure) && StoreFailedToLoad(policy))
		{
			first_failure = policy.load_result;
		}
	}
	return first_failure;
}
CATCH_RETURN()

HRESULT
AnalyzeFirewallRulesReferencingAppPackages()
{
	for (auto& policy : g_policy_objects)
	{
		if (StoreFailedToLoad(policy))
		{
			PrintStoreLoadFailure(policy);
			continue;
		}

		std::vector<std::wstring> rules_with_pfn{};
		std::vector<std::wstring> rules_with_package_id_without_pfn{};
		std::vector<std::wstring> rules_with_package_naming_without_package_id_or_pfn{};
		for (const auto& rule : policy.normalizedRules)
		{
			// a rule whose schema version predates the PFN field is classified as if its PFN were empty
			const auto package_family_name = rule.PackageFamilyName();
			if (package_family_name && package_family_name[0] != L'\0')
			{
				rules_with_pfn.emplace_back(rule.fw_rule->wszRuleId);
			}
			else if (rule.fw_rule->wszPackageId && rule.fw_rule->wszPackageId[0] != L'\0')
			{
				rules_with_package_id_without_pfn.emplace_back(rule.fw_rule->wszRuleId);
			}
			else if (!rule.rule_name.value.empty() && rule.rule_name.value[0] == L'@')
			{
				rules_with_package_naming_without_package_id_or_pfn.emplace_back(rule.fw_rule->wszRuleId);
			}
		}

		if (rules_with_pfn.empty() && rules_with_package_id_without_pfn.empty() &&
		    rules_with_package_naming_without_package_id_or_pfn.empty())
		{
			continue;
		}

		const auto print_category = [&](PCWSTR description, const std::vector<std::wstring>& rule_ids)
		{
			wprintf(
			    L"*** Firewall Rules in %hs Store %ws [%zu rules] ***\n",
			    policy.store_type_string,
			    description,
			    rule_ids.size());
			if (VerboseOutputEnabled())
			{
				for (const auto& rule_id : rule_ids)
				{
					wprintf(L"  RuleId: %ws\n", rule_id.c_str());
				}
				wprintf(L"\n\n");
			}
		};

		wprintf(L"\n\n");
		print_category(L"with a Package Family Name", rules_with_pfn);
		print_category(L"with a Package ID and no Package Family Name", rules_with_package_id_without_pfn);
		print_category(
		    L"without a Package ID or Package Family Name but a Firewall name that looks like a package-name",
		    rules_with_package_naming_without_package_id_or_pfn);
	}

	return S_OK;
}

static std::string
PrintFirewallAction(const std::optional<int32_t>& value)
{
	if (!value.has_value())
	{
		return "Unavailable";
	}
	switch (*value)
	{
	case 0:
		return "Not Configured";
	case 2:
		return "Allow";
	case 4:
		return "Block";
	default:
		return "<Unknown Action value: " + std::to_string(*value) + ">";
	}
}

static std::string
PrintFirewallBoolean(const std::optional<int32_t>& value)
{
	if (!value.has_value())
	{
		return "Unavailable";
	}
	switch (*value)
	{
	case 0:
		return "False";
	case 1:
		return "True";
	case 2:
		return "Not Configured";
	default:
		return "<Unknown Boolean value: " + std::to_string(*value) + ">";
	}
}

static NET_FW_PROFILE_TYPE2
StringToEnum(PCWSTR profile_string)
{
	if (_wcsicmp(profile_string, L"Domain") == 0)
	{
		return NET_FW_PROFILE2_DOMAIN;
	}
	if (_wcsicmp(profile_string, L"Private") == 0)
	{
		return NET_FW_PROFILE2_PRIVATE;
	}
	if (_wcsicmp(profile_string, L"Public") == 0)
	{
		return NET_FW_PROFILE2_PUBLIC;
	}
	THROW_HR_MSG(E_INVALIDARG, "Invalid profile string: %ls", profile_string);
}

static std::string
PrintFirewallProfileBitmask(uint32_t profile_bitmask)
{
	std::string result;
	if (profile_bitmask & NET_FW_PROFILE2_DOMAIN)
	{
		result += "Domain ";
	}
	if (profile_bitmask & NET_FW_PROFILE2_PRIVATE)
	{
		result += "Private ";
	}
	if (profile_bitmask & NET_FW_PROFILE2_PUBLIC)
	{
		result += "Public ";
	}

	if (result.empty())
	{
		return "<No Profiles>";
	}

	// trim trailing space
	result.pop_back();
	return result;
}

namespace
{
enum class NullProfileProperty : uint8_t
{
	Unavailable,
	EmptyValue
};
} // namespace

template <typename T>
static std::optional<T>
ReadFirewallProfileProperty(
    const ctl::ctWmiInstance& profile,
    PCWSTR source,
    PCWSTR property,
    FirewallProfileData& data,
    std::initializer_list<int32_t> acceptable_values = {},
    NullProfileProperty nullHandling = NullProfileProperty::Unavailable)
{
	wil::unique_variant variant;
	HRESULT error = profile.get_no_throw(source, variant.addressof());
	T value{};
	if (SUCCEEDED(error))
	{
		try
		{
			if (ctl::ctWmiReadFromVariant(variant.addressof(), &value))
			{
				if constexpr (std::is_same_v<T, int32_t>)
				{
					if (!acceptable_values.empty() &&
					    std::ranges::find(acceptable_values, value) == acceptable_values.end())
					{
						std::printf(" ** Unknown firewall profile value for %ls: %d **\n", source, value);
						data.diagnostics.push_back(
						    {.property = property,
						     .operation = L"IWbemClassObject::Get",
						     .message = L"The policy value is not recognized; its raw code is preserved.",
						     .sourceProperty = source,
						     .unknownValue = value});
					}
				}
				return value;
			}
			if (nullHandling == NullProfileProperty::EmptyValue)
			{
				return T{};
			}
			error = WBEM_E_VALUE_OUT_OF_RANGE;
		}
		catch (const wil::ResultException& ex)
		{
			error = ex.GetErrorCode();
		}
	}
	std::printf(" ** Failed to read firewall profile property %ls (0x%lx) **\n", source, error);
	data.diagnostics.push_back(
	    {.property = property,
	     .operation = L"IWbemClassObject::Get",
	     .message = std::wstring(L"Could not read firewall profile property ") + source + L".",
	     .sourceProperty = source,
	     .error = error});
	return std::nullopt;
}

static std::optional<bool>
ReadShieldsUp(FirewallProfileData& data)
{
	const auto* profile_name = data.name.has_value() ? data.name->c_str() : L"(unavailable)";
	HRESULT error = E_INVALIDARG;
	try
	{
		THROW_HR_IF(E_INVALIDARG, !data.name.has_value());
		const auto profile_type = StringToEnum(profile_name);
		const auto firewallPolicy2 = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();
		VARIANT_BOOL isShieldsUpEnabled{FALSE};
		error = firewallPolicy2->get_BlockAllInboundTraffic(profile_type, &isShieldsUpEnabled);
		if (SUCCEEDED(error))
		{
			return isShieldsUpEnabled == VARIANT_TRUE;
		}
	}
	catch (const wil::ResultException& ex)
	{
		error = ex.GetErrorCode();
	}
	std::printf(
	    " ** Failed to get BlockAllInboundTraffic for profile %ls from INetFwPolicy2 (0x%lx) **\n",
	    profile_name,
	    error);
	data.diagnostics.push_back(
	    {.property = L"blockAllInboundTraffic",
	     .operation = L"INetFwPolicy2::get_BlockAllInboundTraffic",
	     .message = L"Could not read the Shields-Up setting.",
	     .error = error});
	return std::nullopt;
}

static void
SetShieldsUp(const std::vector<NET_FW_PROFILE_TYPE2>& profiles, bool enabled)
{
	const VARIANT_BOOL isShieldsUpEnabled{enabled ? VARIANT_TRUE : VARIANT_FALSE};

	wil::com_ptr<INetFwPolicy2> firewallPolicy2 = wil::CoCreateInstance<NetFwPolicy2, INetFwPolicy2>();
	for (const auto& profile : profiles)
	{
		HRESULT hr = firewallPolicy2->put_BlockAllInboundTraffic(profile, isShieldsUpEnabled);
		if (SUCCEEDED(hr))
		{
			std::printf(
			    " ** Successfully set BlockAllInboundTraffic to %s for profile %hs\n",
			    enabled ? "true" : "false",
			    PrintFirewallProfileBitmask(profile).c_str());
		}
		else
		{
			std::printf(
			    " ** Failed to set BlockAllInboundTraffic for profile %hs from INetFwPolicy2 (0x%lx) **\n",
			    PrintFirewallProfileBitmask(profile).c_str(),
			    hr);
			RecordOperationFailure(hr);
		}
	}
}

void
ProcessFirewallPolicy(PCWSTR command) noexcept
try
{
	// PolicyStore is a context object to be passed to MSFT_NetFirewallProfile
	// analogous to the powershell command: Get-NetFirewallProfile -PolicyStore ActiveStore
	constexpr auto* policyStoreValue = L"ActiveStore";
	const wil::com_ptr<IWbemContext> policyStoreContext = wil::CoCreateInstance<WbemContext, IWbemContext>();
	THROW_IF_FAILED(
	    policyStoreContext->SetValue(L"PolicyStore", 0, wil::make_variant_bstr(policyStoreValue).addressof()));

	std::wstring banner_header;
	banner_header.insert(banner_header.begin(), g_minimumBannerSize, L'*');

	auto banner_output =
	    wil::str_printf<std::wstring>(L"Analyzing the currently active Firewall Profile configuration");
	const size_t prefix_spaces =
	    banner_header.size() > banner_output.size() ? (banner_header.size() - banner_output.size()) / 2 : 0;
	banner_output.insert(0, prefix_spaces, L' ');

	if (banner_output.size() > banner_header.size())
	{
		banner_header.insert(banner_header.end(), banner_output.size() - banner_header.size(), L'*');
	}

	std::printf(
	    "\n"
	    "%ls\n"
	    "%ls\n"
	    "%ls\n",
	    banner_header.c_str(),
	    banner_output.c_str(),
	    banner_header.c_str());

	for (const auto& profile :
	     ctl::ctWmiEnumerateInstance::Query(L"SELECT * FROM MSFT_NetFirewallProfile", policyStoreContext))
	{
		FirewallProfileData data;
		data.name = ReadFirewallProfileProperty<std::wstring>(profile, L"Name", L"profile", data);
		data.enabled = ReadFirewallProfileProperty<int32_t>(profile, L"Enabled", L"enabled", data, {0, 1, 2});
		data.defaultInboundAction = ReadFirewallProfileProperty<int32_t>(
		    profile,
		    L"DefaultInboundAction",
		    L"defaultInboundAction",
		    data,
		    {0, 2, 4});
		data.defaultOutboundAction = ReadFirewallProfileProperty<int32_t>(
		    profile,
		    L"DefaultOutboundAction",
		    L"defaultOutboundAction",
		    data,
		    {0, 2, 4});
		data.allowInboundRules =
		    ReadFirewallProfileProperty<int32_t>(profile, L"AllowInboundRules", L"allowInboundRules", data, {0, 1, 2});
		data.allowLocalFirewallRules = ReadFirewallProfileProperty<int32_t>(
		    profile,
		    L"AllowLocalFirewallRules",
		    L"allowLocalFirewallRules",
		    data,
		    {0, 1, 2});
		data.allowUserApps =
		    ReadFirewallProfileProperty<int32_t>(profile, L"AllowUserApps", L"allowUserApps", data, {0, 1, 2});
		data.allowUserPorts =
		    ReadFirewallProfileProperty<int32_t>(profile, L"AllowUserPorts", L"allowUserPorts", data, {0, 1, 2});
		data.allowUnicastResponseToMulticast = ReadFirewallProfileProperty<int32_t>(
		    profile,
		    L"AllowUnicastResponseToMulticast",
		    L"allowUnicastResponseToMulticast",
		    data,
		    {0, 1, 2});

		// Null aliases mean no interfaces are disabled, not a failed property read.
		data.disabledInterfaceAliases = ReadFirewallProfileProperty<std::vector<std::wstring>>(
		    profile,
		    L"DisabledInterfaceAliases",
		    L"disabledInterfaceAliases",
		    data,
		    {},
		    NullProfileProperty::EmptyValue);
		data.blockAllInboundTraffic = ReadShieldsUp(data);

		std::printf(
		    "Firewall Policies for profile: %ls\n"
		    "    Enabled: %ls\n"
		    "    Shield's Up (block all inbound traffic): %hs\n"
		    "    Default Inbound Action: %hs\n"
		    "    Default Outbound Action: %hs\n"
		    "    Allow Inbound Rules: %hs\n"
		    "    Allow Local Firewall Rules: %hs\n"
		    "    Allow User Apps: %hs\n"
		    "    Allow User Ports: %hs\n"
		    "    Allow Unicast Response To Multicast: %hs\n",
		    data.name.has_value() ? data.name->c_str() : L"Unavailable",
		    data.enabled.has_value() ? std::to_wstring(*data.enabled).c_str() : L"Unavailable",
		    data.blockAllInboundTraffic.has_value() ? (*data.blockAllInboundTraffic ? "Enabled" : "Disabled")
		                                            : "Unavailable",
		    PrintFirewallAction(data.defaultInboundAction).c_str(),
		    PrintFirewallAction(data.defaultOutboundAction).c_str(),
		    PrintFirewallBoolean(data.allowInboundRules).c_str(),
		    PrintFirewallBoolean(data.allowLocalFirewallRules).c_str(),
		    PrintFirewallBoolean(data.allowUserApps).c_str(),
		    PrintFirewallBoolean(data.allowUserPorts).c_str(),
		    PrintFirewallBoolean(data.allowUnicastResponseToMulticast).c_str());
		if (!data.disabledInterfaceAliases.has_value())
		{
			wprintf(L"    Disabled Interface Aliases: Unavailable\n");
		}
		else if (data.disabledInterfaceAliases->empty())
		{
			wprintf(L"    Disabled Interface Aliases: None\n");
		}
		else
		{
			wprintf(L"    Disabled Interface Aliases:\n");
			for (const auto& name : *data.disabledInterfaceAliases)
			{
				wprintf(L"    %ws\n", name.c_str());
			}
		}

		std::printf("\n");
		WriteFirewallProfileJson(data, command);
	}
}
catch (const std::exception& ex)
{
	std::printf("An unexpected error occurred while processing firewall policies: %s\n", ex.what());
	RecordProfileJsonFailure(command, wil::ResultFromCaughtException(), ex.what());
	RecordOperationFailure(wil::ResultFromCaughtException());
}

void
ProcessFirewallRules()
{
	for (auto& policy : g_policy_objects)
	{
		// cannot directly modify MDM or GP rules locally
		if (CleanBrokenRulesEnabled() && StoreAllowsOnlyReadAccess(policy.store_type))
		{
			std::wstring banner_header;
			banner_header.insert(banner_header.begin(), g_minimumBannerSize, L'*');

			std::printf(
			    "\n"
			    "%ls\n"
			    "  Skipping the %hs Firewall Policy Store\n"
			    "%ls\n"
			    "  NOTE: The %hs Firewall Policy Store cannot be modified locally.\n"
			    "        Skipping any deletion of rules in this store.\n",
			    banner_header.c_str(),
			    policy.store_type_string,
			    banner_header.c_str(),
			    policy.store_type_string);
			WriteFirewallRuleStatusJson(policy, 0, {}, L"clean_rules", RuleStatusAnalysis::NotPerformed);
			WriteCleanupSkippedStoreJson(policy, L"clean_rules");
			continue;
		}

		// declared outside the try, so the actions taken before an exception are still reported
		StoreCleanup cleanup;
		bool cleanup_started = false;
		const auto writeInterruptedCleanup = [&](HRESULT error) noexcept
		{
			if (!cleanup_started)
			{
				return;
			}
			try
			{
				WriteCleanupJson(policy, cleanup, L"clean_rules", error);
			}
			catch (...)
			{
				RecordOperationFailure(wil::ResultFromCaughtException());
			}
		};

		try
		{
			std::wstring banner_header;
			banner_header.insert(banner_header.begin(), g_minimumBannerSize, L'*');

			auto banner_output =
			    wil::str_printf<std::wstring>(L"Analyzing the %hs Firewall Policy Store", policy.store_type_string);
			const size_t prefix_spaces =
			    banner_header.size() > banner_output.size() ? (banner_header.size() - banner_output.size()) / 2 : 0;
			banner_output.insert(0, prefix_spaces, L' ');

			if (banner_output.size() > banner_header.size())
			{
				banner_header.insert(banner_header.end(), banner_output.size() - banner_header.size(), L'*');
			}

			std::printf(
			    "\n"
			    "%ls\n"
			    "%ls\n"
			    "%ls\n",
			    banner_header.c_str(),
			    banner_output.c_str(),
			    banner_header.c_str());

			if (StoreFailedToLoad(policy) || policy.normalizedRules.empty())
			{
				if (StoreFailedToLoad(policy))
				{
					PrintStoreLoadFailure(policy);
				}
				else
				{
					std::printf("  * No Rules in this store\n");
				}
				WriteFirewallRuleStatusJson(
				    policy,
				    0,
				    {},
				    CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules",
				    RuleStatusAnalysis::NotPerformed);
				continue;
			}

			ChronoTimer timer;
			timer.start("SortRulesByName");
			details::SortRulesByName(policy.normalizedRules);
			timer.end();

			timer.start("CheckForRulesWithErrorStatus");
			details::CheckForRulesWithErrorStatus(policy);
			timer.end();

			if (VerboseOutputEnabled())
			{
				std::printf("\n");
			}
			timer.start("CheckForMissingAppRules");
			details::CheckForMissingAppRules(policy);
			timer.end();

			if (VerboseOutputEnabled())
			{
				std::printf("\n");
			}
			timer.start("CheckForMissingAppPackage");
			details::CheckForMissingAppPackage(policy);
			timer.end();

			if (CleanBrokenRulesEnabled())
			{
				std::printf("\n");
				cleanup_started = true;
				DeleteMissingAppRules(
				    policy.normalizedRules,
				    std::wcin,
				    [&policy](PCWSTR ruleId)
				    {
					    return g_FWDeleteFirewallRule(policy.store_handle, ruleId);
				    },
				    cleanup);
			}

			if (VerboseOutputEnabled())
			{
				std::printf("\n");
			}
			timer.start("CheckUnresolvedUserAccountRules");
			details::CheckUnresolvedUserAccountRules(policy);
			timer.end();

			if (CleanBrokenRulesEnabled())
			{
				std::printf("\n");
				DeleteUnresolvedUserAccountRules(
				    policy.normalizedRules,
				    std::wcin,
				    [&policy](PCWSTR ruleId)
				    {
					    return g_FWDeleteFirewallRule(policy.store_handle, ruleId);
				    },
				    cleanup);
			}

			if (VerboseOutputEnabled())
			{
				std::printf("\n");
			}

			timer.start("RankRulesByFilterCounts");
			details::RankRulesByFilterCounts(policy);
			timer.end();

			timer.start("Counting duplicate rules");
			const auto duplicateRules =
			    details::CheckForDuplicateRules(policy, CleanBrokenRulesEnabled() ? L"clean_rules" : L"analyze_rules");
			timer.end();

			if (CleanBrokenRulesEnabled())
			{
				std::printf("\n");
				DeleteDuplicateRules(
				    duplicateRules,
				    std::wcin,
				    [&policy](PCWSTR ruleId)
				    {
					    return g_FWDeleteFirewallRule(policy.store_handle, ruleId);
				    },
				    cleanup);
				// a failure writing it is not reported again as an interrupted cleanup
				cleanup_started = false;
				WriteCleanupJson(policy, cleanup, L"clean_rules", S_OK);
			}
		}
		catch (const wil::ResultException& ex)
		{
			std::printf(" -- an error occurred (0x%lx) -- \n", ex.GetErrorCode());
			RecordOperationFailure(ex.GetErrorCode());
			writeInterruptedCleanup(ex.GetErrorCode());
		}
		catch (const std::exception& ex)
		{
			std::printf(" -- an unexpected error occurred: %s -- \n", ex.what());
			RecordOperationFailure(wil::ResultFromCaughtException());
			writeInterruptedCleanup(wil::ResultFromCaughtException());
		}
	}
}

void
ProcessInboundRules()
{
	for (auto& policy : g_policy_objects)
	{
		try
		{
			std::wstring banner_header;
			banner_header.insert(banner_header.begin(), g_minimumBannerSize, L'*');

			auto banner_output = wil::str_printf<std::wstring>(
			    L"Analyzing rules allowing Inbound connectivity in the %hs Firewall Policy Store",
			    policy.store_type_string);
			const size_t prefix_spaces =
			    banner_header.size() > banner_output.size() ? (banner_header.size() - banner_output.size()) / 2 : 0;
			banner_output.insert(0, prefix_spaces, L' ');

			if (banner_output.size() > banner_header.size())
			{
				banner_header.insert(banner_header.end(), banner_output.size() - banner_header.size(), L'*');
			}
			std::printf(
			    "\n"
			    "%ls\n"
			    "%ls\n"
			    "%ls\n",
			    banner_header.c_str(),
			    banner_output.c_str(),
			    banner_header.c_str());

			if (StoreFailedToLoad(policy))
			{
				PrintStoreLoadFailure(policy);
				continue;
			}

			ChronoTimer timer;
			timer.start("AnalyzeInboundRules");
			const auto inbound_rule_analysis = details::AnalyzeInboundRules(policy.normalizedRules);
			timer.end();

			timer.start("PrintInboundRuleAnalysis");
			details::PrintInboundRuleAnalysis(inbound_rule_analysis);
			timer.end();
		}
		catch (const wil::ResultException& ex)
		{
			std::printf(" -- an error occurred (0x%lx) -- \n", ex.GetErrorCode());
			RecordOperationFailure(ex.GetErrorCode());
		}
		catch (const std::exception& ex)
		{
			std::printf(" -- an unexpected error occurred: %s -- \n", ex.what());
			RecordOperationFailure(wil::ResultFromCaughtException());
		}
	}
}

void
ProcessShieldsUp() noexcept
{
	const auto profile = GetShieldsUpProfiles();
	if (TurnOffShieldsUpSet())
	{
		SetShieldsUp(profile, false);
	}
	else if (TurnOnShieldsUpSet())
	{
		SetShieldsUp(profile, true);
	}
	else
	{
		FAIL_FAST();
	}

	ProcessFirewallPolicy(L"shields_up_change");
}