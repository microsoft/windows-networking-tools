#pragma once
#include <vector>
#include "NormalizedFirewallRule.h"

struct DuplicateRuleDetails
{
	const std::vector<NormalizedFirewallRule>::iterator duplicate_rule_begin;
	const std::vector<NormalizedFirewallRule>::iterator duplicate_rule_end;
};

struct FirewallPolicyObjects
{
	FW_STORE_TYPE type;
	PCSTR type_string;
	std::vector<NormalizedFirewallRule> normalizedRules;
};

void LoadFirewallFunctions();
HRESULT LoadFirewallRulesFromStore(FirewallPolicyObjects& firewall_rules);
bool HasFirewallAdminAccess();

std::vector<DuplicateRuleDetails> CheckForDuplicateRules(std::vector<NormalizedFirewallRule>& normalized_rules);
void DeleteDuplicateRules(const std::vector<DuplicateRuleDetails>& duplicate_rules);

void CheckForMissingAppRules(const std::vector<NormalizedFirewallRule>& normalized_rules);
void DeleteMissingAppRules(const std::vector<NormalizedFirewallRule>& normalized_rules);

void CheckUnresolvedUserAccountRules(std::vector<NormalizedFirewallRule>& normalized_rules, FW_STORE_TYPE store_type);
void DeleteUnresolvedUserAccountRules(const std::vector<NormalizedFirewallRule>& normalized_rules);

void CheckForRulesWithErrorStatus(const std::vector<NormalizedFirewallRule>& normalized_rules);
