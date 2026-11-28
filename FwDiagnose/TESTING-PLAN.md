# FwDiagnose test plan

Status (2026-11-27): rule printing, the per-store analyses, all three `-clean-rules` deletions with their recorded action history, and the JSON report sections, including `cleanup` and `cleanupSummary`, are covered (see the tables below). Next: Review 9, finishing `-analyze-rules` in JSON-OUTPUT-PLAN.md.

Principles: tests use synthetic data only, never read or change system firewall/WFP state, and return nonzero on failure. One test project per area, compiling the module's `.cpp` as a project source (like `FirewallRulePrintTests`), with stubs for global flags (`VerboseOutputEnabled`, `DebugOutputEnabled`).

## Phase 1 - pure functions (no seams needed)
| Area | Units | Key cases |
|---|---|---|
| Rule normalization | `NormalizedFirewallRule` ctor, `RuleDetailsComparison` + `ComparisonPolicy` | each policy flag relaxes only its step; name/ID/description/version excluded; status/origin included; 2.27 vs 2.33 rules compare equal when common fields match |
| Rule printing | `PrintRule`, `PrintRuleContents` (done: `FirewallRulePrintTests`) | same labels across versions/protocols; common values match across 2.27/2.31/2.33; placeholders; effective policy for empty conditions, including keyword-only restrictions; resolved user without embedded null |
| Keyword/format helpers | `AddressKeywordToString`, `PortKeywordToString`, `PortRangesToString`, `IcmpTypeCodeConstraintsToString` (partly covered through `PrintRuleContents`), enum `ToString`s | single/multiple/unknown bits; no trailing separators |
| Path classification | `ContainsPerUserEnvironmentVariable`, `ContainsServiceProfileEnvironmentVariable`, `IsRuleAnAppxRule` | case-insensitivity, partial matches |
| Inbound analysis | `IsInboundAllowRule`, `GetInboundProfileCategory`, `AnalyzeInboundRules` | profile buckets, local-subnet handling |
| Duplicates | `AnalyzeDuplicateRules`, `PrintDuplicateAnalysis`, `ReturnDuplicateKeepChoices`, `DeleteDuplicateRules` (done: `FirewallRulePrintTests`; JSON in `ProfileJsonReportTests`) | sets found; profile and active-flag differences each prevent a match; name/ID/description excluded; set and rule order; null names and IDs; keep choices; each prompt answer, end of input, and a failed deletion, with scripted input and a fake delete function |
| Package and application analysis | `AnalyzePackageRules`, `PrintPackageAnalysis`, `AnalyzeApplicationRules`, `PrintApplicationAnalysis`, `ProcessPackageIdentity` (done: `FirewallRulePrintTests`) | SID failures kept only when the packages loaded, in order; a family-name failure prints a WARNING, a full-name failure prints only with `-verbose`; a rule's package ID, or the SID derived from a family-name-only rule, including a family name over 64 characters and schema version 31; findings and deletion records keep their rule's identity after reordering; a rule whose path could not be expanded is unchecked, not missing |
| WFP formatting | `FwpmLayerToString`, `Built-in*ToString`, `IpProtocolToString`, discard-reason and ICMP type/code strings, `PrintNetEvent*` with synthetic events | known GUIDs, unknown/third-party paths, version-specific event fields |
| JSON report | `ProfileJsonReportTests` (done for `-analyze-rules`, `-clean-rules`, and Shields Up) | result and run status computation: completed, partial for each incomplete store, section, error diagnostic, family-name SID failure, or interrupted store, failed when stopped early; `json_export_incomplete` only for a Shields Up change; `WriteStoreInterruptedJson` on completed, missing, and not_present stores and after the report finishes; package identity keys and order on every rule entry; unchecked application rules; `app_container_sid_not_derived` severity by name kind |

## Phase 2 - seams for Windows APIs
- Firewall: inject the FirewallAPI function table (already resolved at runtime in `LoadFirewallFunctions`) so `LoadFirewallRulesFromStore` can be fed synthetic rule arrays per store and version, including `ERROR_FILE_NOT_FOUND` and other failures.
- App packages, IP properties, WFP enumerations: separate "collect" from "analyze" so analyses take vectors rather than globals.
- Deletion paths: `DeleteMissingAppRules` (`ApplicationAnalysis.cpp`), `DeleteUnresolvedUserAccountRules` (`UserOwnerAnalysis.cpp`), and `DeleteDuplicateRules` take the input stream and a `DeleteFirewallRuleFunction` (`RuleDeletion.h`), and are tested with scripted answers and a fake delete function (done: each answer, end of input, a failed deletion, rules not checked or already deleted, and a rule deleted by one phase not offered by a later one). Each also records a `CleanupAction` per proposal into a `StoreCleanup`; tests check decisions, approval sources, outcomes, counts, and that records keep naming the right rules after the store's rules are reordered. `AskAgainAtEndOfInput` is tested with streams; the real console path (Ctrl+Z at `std::wcin`) is manual. Callout removal still needs this seam.

## Phase 3 - real firewall rules at each schema version (test machine only)
- Script or test executable that opens the Local store at 2.27, 2.31, and 2.33 with `FWOpenPolicyStore`, adds rules in a dedicated rule group using a broad set of fields (service, application, package ID/PFN, owner SID, authorization lists, address keywords and lists, TCP/UDP ports and keywords, ICMPv4/v6 type/codes, interfaces, dynamic keywords), runs `-analyze-rules` and `-analyze-inbound-rules -verbose`, compares the output against expected label sets, and deletes the group even on failure.
- Mutates the firewall, so it runs only on a dedicated test VM.

## Phase 4 - non-mutating integration smoke tests (manual or scripted)
- Compare output before and after a change: build the previous commit separately, run the same read-only commands with both builds, and diff (non-verbose output should be identical unless the change is intended).
- `FwDiagnose.exe -?`, `-list-app-packages`, `-analyze-app-package-rules`, `-analyze-rules`, `-analyze-inbound-rules`, `-analyze-wfp`, and `-json` with each read-only command; `-wfp-events` and `-tcpip-events` are read-only but run until interrupted; verify exit codes and JSON parses.
- Mutating modes (`-clean-rules`, `-enable-shields-up`, `-disable-shields-up`, `-remove-callouts`) only on a dedicated test VM.

## Decisions
- Static functions that tests need are declared in headers and made non-static, rather than tests including `.cpp` files.
