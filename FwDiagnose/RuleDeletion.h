// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <Windows.h>

#include "RulePackageIdentity.h"

struct NormalizedFirewallRule;

// deletes one rule by its rule ID and returns a Win32 error code, as FWDeleteFirewallRule does
using DeleteFirewallRuleFunction = std::function<DWORD(PCWSTR ruleId)>;

// why -clean-rules proposed deleting a rule or a set of duplicate rules
enum class CleanupReason : uint8_t
{
	MissingApplication,
	UnresolvedUserOwner,
	MissingLocalProfile,
	Duplicate
};

// the answer that decided a cleanup action
enum class CleanupDecision : uint8_t
{
	Yes,
	No,
	// 's': this action and the rest of its category in this store were not deleted
	SkipRemaining,
	// 'a': this action and the rest of its category in this store were deleted without asking
	DeleteAll,
	// the input ended at this action's prompt; counts as 's'
	EndOfInput,
	// not asked: after 'a' it was deleted, after 's' or the end of input it was left alone
	NotPrompted
};

enum class ApprovalSource : uint8_t
{
	None,
	// this action's own prompt was answered 'y' or 'a'
	Prompt,
	// an earlier 'a' in the same category and store
	DeleteAll
};

enum class DeletionOutcome : uint8_t
{
	// the rule of a duplicate set that was not deleted
	Kept,
	Succeeded,
	Failed,
	NotAttempted
};

// the rule's identity is copied when the action is recorded, because the store's rules are reordered
// (by the duplicate analysis) before the JSON is written; nullopt where the rule's field is null
struct RuleDeletionRecord
{
	std::optional<std::wstring> ruleId;
	std::optional<std::wstring> name;
	std::optional<std::wstring> application;
	std::optional<std::wstring> localUserOwnerSid;
	std::optional<RulePackageIdentity> packageIdentity;
	DeletionOutcome outcome{DeletionOutcome::NotAttempted};
	// HRESULT_FROM_WIN32 of the deletion's error when the outcome is Failed
	HRESULT error{S_OK};
};

// the question asked when the rules of a duplicate set have different names
struct DuplicateKeepRecord
{
	std::vector<std::wstring> choices;
	// the number entered, starting at 1; nullopt when the input ended, so every rule was kept
	std::optional<size_t> answer;
};

// one prompted rule, or one set of duplicate rules
struct CleanupAction
{
	CleanupReason reason{CleanupReason::MissingApplication};
	CleanupDecision decision{CleanupDecision::NotPrompted};
	ApprovalSource approvalSource{ApprovalSource::None};
	// one record for a single rule; every rule of the set, in set order, for duplicates
	std::vector<RuleDeletionRecord> rules;
	// duplicates only: the position in rules of the rule that was kept, when deletion was attempted
	std::optional<size_t> keptRuleIndex;
	// duplicates only: present when the names differed and the question was asked
	std::optional<DuplicateKeepRecord> keepChoice;
};

// a record for the rule, not yet attempted, with its identity copied
RuleDeletionRecord
ReturnRuleDeletionRecord(const NormalizedFirewallRule& rule);

// what -clean-rules did in one store, in the order it was done
struct StoreCleanup
{
	std::vector<CleanupAction> actions;
};

// counted in rules proposed for deletion: for a set of duplicates, every rule but the one kept
// candidate == attempted + declined + skipped, and attempted == succeeded + failed
struct CleanupCounts
{
	size_t candidate{};
	size_t attempted{};
	size_t succeeded{};
	size_t failed{};
	size_t declined{};
	size_t skipped{};
};

//
// CountCleanup
//
// Counts the rules that one store's cleanup proposed, deleted, failed to delete, and left alone.
//
// Parameters:
//   cleanup [in] - the actions recorded by the deletion functions for one store
//
// Returns:
//   The counts; 'n' answers are declined, and everything else not attempted is skipped.
//
inline CleanupCounts
CountCleanup(const StoreCleanup& cleanup) noexcept
{
	CleanupCounts counts;
	for (const auto& action : cleanup.actions)
	{
		const size_t proposed = action.reason == CleanupReason::Duplicate
		                            ? (action.rules.empty() ? 0 : action.rules.size() - 1)
		                            : action.rules.size();
		counts.candidate += proposed;

		size_t succeeded = 0;
		size_t failed = 0;
		for (const auto& record : action.rules)
		{
			if (record.outcome == DeletionOutcome::Succeeded)
			{
				++succeeded;
			}
			else if (record.outcome == DeletionOutcome::Failed)
			{
				++failed;
			}
		}

		if (succeeded + failed > 0)
		{
			counts.attempted += succeeded + failed;
			counts.succeeded += succeeded;
			counts.failed += failed;
		}
		else if (action.decision == CleanupDecision::No)
		{
			counts.declined += proposed;
		}
		else
		{
			counts.skipped += proposed;
		}
	}
	return counts;
}
