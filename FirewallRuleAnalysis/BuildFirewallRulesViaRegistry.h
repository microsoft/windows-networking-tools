#pragma once
#include <string>
#include <vector>

#include "NormalizedFirewallRule.h"

enum class FirewallRuleRegistryStore
{
    Local,
    AppIsolation
};

std::vector<std::tuple<std::wstring, NormalizedFirewallRule>> BuildFirewallRulesViaRegistry(FirewallRuleRegistryStore store);

size_t CountDuplicateFirewallRules(const std::vector<std::tuple<std::wstring, NormalizedFirewallRule>>& rules);
