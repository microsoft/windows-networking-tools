// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <functional>

#include <Windows.h>

// deletes one rule by its rule ID and returns a Win32 error code, as FWDeleteFirewallRule does
using DeleteFirewallRuleFunction = std::function<DWORD(PCWSTR ruleId)>;
