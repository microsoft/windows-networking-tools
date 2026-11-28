# FwDiagnose JSON Output Plan

## Current status and next steps

Last updated 2026-11-27, at commit `14c87c8` on branch `khorton/FirewallRuleAnalysis` (pushed), plus the step 1 tests and these notes (not committed yet).

### Where we left off

- Reviews 1-7 (section 9) are implemented, tested, documented, and pushed. Every per-store analysis that `-analyze-rules` prints is now in the JSON report: `firewallProfiles`, and per store `ruleDetails`, `applicationAnalysis`, `packageAnalysis`, `userOwnerAnalysis`, `filterRankings`, and `duplicateAnalysis`.
- Each analysis lives in its own module (`ApplicationAnalysis`, `PackageAnalysis`, `UserOwnerAnalysis`, `FilterRanking`, `DuplicateAnalysis`) and returns one result that both the console text and the JSON are written from.
- All three `-clean-rules` deletions take the input stream and delete function as parameters and are tested with scripted answers and a fake delete function: `DeleteMissingAppRules` (`ApplicationAnalysis.cpp`), `DeleteUnresolvedUserAccountRules` (`UserOwnerAnalysis.cpp`), and `DeleteDuplicateRules` (`DuplicateAnalysis.cpp`). The shared `DeleteFirewallRuleFunction` type is in `RuleDeletion.h`.
- Every report is still marked `partial` with a `json_export_incomplete` warning (`ProfileJsonReport.cpp`, about line 180), and the console prints a NOTE listing the exported sections (`FwDiagnose.cpp`, about line 800).
- Tests: `NormalizedStringTests`, `FirewallRulePrintTests` (1294 checks), and `ProfileJsonReportTests` all pass.
- **Fixed after resuming:** under `-clean-rules`, duplicate deletion could delete rules the user chose to keep. The missing-application and unresolved-SID phases never set `is_rule_deleted`, and duplicate analysis did not check it; copies of a duplicate share every setting, so the duplicate phase could keep a copy an earlier phase had deleted and delete the copies the user kept. Now all three phases mark the rules they delete, and `AnalyzeDuplicateRules` leaves deleted rules out of the sets (a set with one rule left is not a duplicate). `TestDuplicateAnalysisSkipsDeletedRules` and `TestDeleteDuplicateRulesSkipsDeletedRules` cover the duplicate part; `-analyze-rules` output is unchanged.
- Still open, for Review 8: in `-clean-rules`, the unresolved-SID analysis and filter rankings still count rules the earlier phases deleted, while duplicate analysis no longer does.

### What to do next, in order

1. **Review 8: `-clean-rules` action history.** Propose the JSON for section 3's `-clean-rules` schema: one action record per prompted rule or set (reason, store, rule ID, decision, approval source, outcome, error), which rule was kept for duplicates, and the attempted, succeeded, failed, and skipped counts. Get approval, then implement it from the deletion functions' results (have them return their decisions rather than only printing).
2. **Review 9: finish `-analyze-rules`.** Check whether any console output of `-analyze-rules` is still not exported. If nothing is left, stop marking `analyze_rules` partial: drop its `json_export_incomplete` warning, let `run.status` become `completed`, and update the console NOTE, `-?` help (`FwDiagnose.cpp`, about line 218), COMMAND-LINE.md, and the tests.
3. **Then the other commands**, one review each, in this order: `-analyze-inbound-rules` (currently rejected with `-json`), `-list-app-packages`, `-analyze-app-package-rules`, `-analyze-wfp`, Shields Up outcomes, and callout removal and restoration.
4. **Later:** `-jsonl` for `-wfp-events` and `-tcpip-events` (sections 4-6), and formal JSON Schema files (section 7, step 1).

### How each review is done

1. Propose the console and JSON design (a worked example like Reviews 1-7), and get the user's approval before coding.
2. Put the analysis in its own module that returns a result. Write both the console text and the JSON from that result, never by querying again.
3. Add console tests to `tests\FirewallRulePrintTests.cpp` and JSON tests to `tests\ProfileJsonReportTests.cpp`. Use synthetic rules only; never change the machine's firewall state.
4. Build the solution, run the three test executables, and compare live read-only output (`.\x64\Debug\FwDiagnose.exe -analyze-rules [-verbose] -json <path>`) before and after the change.
5. Add a Review section below and update COMMAND-LINE.md, ARCHITECTURE.md, and TESTING-PLAN.md.
6. Commit and push only when the user asks.

### Squad agents for each step

Every round that changes code ends with an independent review by **vault** and **bug-hunter**, plus the mandatory **security-sdl** gate. No agent reviews its own work.

| Step | Agents |
|---|---|
| Resume | No agent: build the solution, run the three test executables, and save a read-only `-analyze-rules -json` baseline. |
| Deletion bug (done) | **forge** fixed it; **tester** wrote the duplicate-phase tests; reviewed by vault, bug-hunter, and security-sdl. |
| Testable deletions (done) | **forge** added the parameters and moved the functions; **tester** wrote the scripted-answer tests; reviewed by vault, bug-hunter, sal-contracts, and security-sdl. |
| 1. Review 8 | **cipher** proposes the console and JSON design for approval; then **forge** and **tester**. |
| 2. Review 9 | **forge** checks for unexported output and removes the partial marking; **vault** validates. |
| 3. Other commands | **forge** and **tester** for each; for callout removal, **sal-contracts** also checks the filter lock and the `TerminateProcess` exit path. |
| Later | **sal-contracts** for thread-safe `-jsonl` event recording; **vm-deployer**, only with approval, for the firewall-changing tests (TESTING-PLAN Phases 3-4). |

Follow `.github/copilot-instructions.md`: tabs, CRLF, no BOM; format only the changed lines with clang-format; `.has_value()`; `enum class` rather than bool parameters; `NormalizedString::AlphabeticalCompare` for any sort a user sees. Every new function gets a comment banner with its purpose, its `[in]`/`[out]` parameters, and its return value, and unusual C++ constructs are explained.

## Agreed behavior

Add structured reporting alongside the existing console output. Do not redirect or parse console text.

- `-json <path>` writes an indented, standard JSON report and overwrites that path.
- `-jsonl <path>` optionally writes JSON Lines for live event captures.
- `-verbose` controls additional information in both the console and the file.
- Existing console output, command execution order, prompts, and event filtering remain unchanged.

This plan covers every command, shared policy summaries, interactive prompts and outcomes, and all currently handled event variants. The schemas below are proposed field-level contracts; formal JSON Schema definitions are the first implementation deliverable.

## 1. Common report structure

Use one versioned envelope, with an ordered `results` array so commands that run together can share one report.

```json
{
  "schemaVersion": "1.0",
  "tool": "FwDiagnose",
  "run": {
    "id": "a-generated-guid",
    "startedAt": "2026-10-11T01:30:00.000Z",
    "finishedAt": "2026-10-11T01:30:04.000Z",
    "requestedCommands": ["analyze_rules"],
    "verbose": false,
    "status": "completed",
    "exitCode": 0
  },
  "results": [
    {
      "command": "analyze_rules",
      "status": "completed",
      "data": {
        "firewallProfiles": [],
        "stores": []
      },
      "diagnostics": []
    }
  ],
  "diagnostics": []
}
```

Important distinctions:

- `run.status` describes execution: `completed`, `partial`, `failed`, or `interrupted`. It does not mean that the firewall configuration is healthy.
- Per-command and per-store statuses distinguish successful empty results from inaccessible, unsupported, missing, or partially enumerated data.
- `exitCode` records the actual process result separately. Some current functions print errors and return without propagating failure.
- Requested commands and actually executed results remain distinct. Several commands currently return early; JSON must not claim other requested commands ran.
- A shared firewall-profile snapshot can appear within the command that produced it, including its collection time.

### Representation conventions

| Data | Proposed representation |
|---|---|
| Property names | Stable `camelCase`; command/event discriminator values use `snake_case` |
| GUIDs and SIDs | Canonical strings, never names substituted for identifiers |
| 64-bit identifiers, LUIDs, weights, SA identifiers | Decimal strings to avoid precision loss in JavaScript and other JSON tools |
| Ordinary counts, ports, indices, enum codes | JSON integers with schema-defined bounds |
| Boolean settings | JSON booleans where genuinely binary |
| Configurable policy settings | Named states such as `true`, `false`, `not_configured`, `unknown`, alongside the raw code |
| Enums | `{ "code": 6, "name": "tcp" }`; unknown values retain their code |
| Flags | Raw mask plus an array of decoded names; retain unknown bits |
| Timestamps | UTC RFC 3339 with fractional seconds; preserve source precision |
| Addresses | Separate address, port, and scope fields |
| Binary values | Explicit encoding, such as `{ "encoding": "hex", "value": "..." }` |
| Collections | Arrays, not objects keyed by display names |
| Missing information | `null` plus an explicit availability/resolution state when the distinction matters |

For verbosity, omit detail collections when they were not requested. An absent verbose-only `rules` array means "not included"; `rules: []` means "included and empty." This avoids confusing LLMs and scripts.

Include short schema descriptions explaining semantics and units. Names, paths, and descriptions originating from the machine are data, not instructions for an AI consumer.

## 2. Shared definitions

Reuse these definitions across command schemas rather than independently reinventing them.

### Firewall policy profile

Collected by `ProcessFirewallPolicy()` in `FirewallRules.cpp:2933`.

Fields:

`profile`, `policyStore`, `enabled`, `blockAllInboundTraffic`, `defaultInboundAction`, `defaultOutboundAction`, `allowInboundRules`, `allowLocalFirewallRules`, `allowUserApps`, `allowUserPorts`, `allowUnicastResponseToMulticast`, `disabledInterfaceAliases`.

Preserve "not configured" versus false, and failed reads versus disabled. The current formatted output can obscure those distinctions.

The `blockAllInboundTraffic` property is an object with `friendlyName: "Shields-Up"` and a boolean `value`. If collection fails, `value` is `null` and a profile-level diagnostic describes the failure. Format short `code`/`state` objects on one line for readability.

### Firewall rule

Use a shared rule definition, with command-specific projections rather than dumping every field everywhere.

Core identity:

`store`, `ruleId`, `name`, `description`, `schemaVersion`, `requestedApiVersion`.

When the corresponding details are presented:

- Classification: `direction`, `action`, `profiles`, `enabled`, `origin`, `status`.
- Targets: `applicationPath`, `serviceName`, `packageSid`, `packageFamilyName`, `localUserOwnerSid`, resolved user/domain.
- Constraints: protocol, address keywords, address ranges/subnets, port keywords/ranges, ICMP type/code lists, interface constraints, authorization lists.
- Extended fields: flags, platform validity, GPO name, metadata counts, network names, security realm, remote server names, FQBN, compartment, provider context, dynamic keyword address IDs.

Version-dependent fields must respect both the negotiated API version and the rule version, as the existing code does.

Use original display strings for export where available. `NormalizedString` is an internal comparison representation; it should not become the authoritative exported spelling.

### Diagnostic

```json
{
  "severity": "warning",
  "code": "referenced_callout_not_found",
  "message": "A filter references a callout not found in the collected inventory.",
  "operation": "resolve_callout",
  "subject": {
    "filterId": "12345",
    "calloutKey": "a-guid"
  },
  "error": null
}
```

Errors include the originating API, raw code, formatted code, and error domain when known. Format all codes as base-16 with a `0x` prefix. Convert Win32 (`DWORD`) codes with `HRESULT_FROM_WIN32` and leave `NTSTATUS` codes unconverted. WFP APIs can return both Win32 errors and HRESULT-style values, so convert every error from `Fwpm*` and `Fwps*` functions the same way; `HRESULT_FROM_WIN32` leaves an existing `HRESULT` unchanged.

## 3. Command-specific schemas

### `-analyze-rules`

This command produces active firewall-profile configuration plus several analyses for each policy store.

Proposed `data`:

| Section | Contents |
|---|---|
| `firewallProfiles` | Shared policy-profile records |
| `stores` | Store identity, negotiated API version, collection/analysis status |
| `ruleDetails` | Total/error rule counts and nonzero partially ignored, ignored, parsing, semantic, runtime, and unknown status categories |
| `applicationAnalysis` | Counts of application-targeted rules, rules whose executable was reported missing, and rules using service-profile variables (implemented; see Review 3) |
| `packageAnalysis` | Package-SID/PFN reference counts and unresolved references (implemented; see Review 4) |
| `userOwnerAnalysis` | SID-owner counts, unresolved owners, and missing local-profile findings (implemented; see Review 5) |
| `filterRankings` | Top rule names by WFP filter count and filter-condition count (implemented; see Review 6) |
| `duplicateAnalysis` | Number of duplicate sets and number of rules in those sets (implemented; see Review 7) |

Under `-verbose`, include the corresponding finding records and rule details, not merely their formatted names.

Two particularly important semantics:

- Duplicate membership is not the same as redundant copies. The current duplicate total includes all members of each duplicate group.
- Rule-to-filter correlation is by name, not a unique rule identifier. Export `correlationMethod: "rule_name"` and the number of rules sharing that name; do not imply an exact one-to-one mapping.

Rankings retain the current top 3 versus top 10 behavior controlled by `-verbose`.

Store identities cover all ten configured stores: Local, Group Policy, RSOP, static/configurable service hardening, static/dynamic interface isolation, application isolation, MDM, and tenant restrictions.

### `-clean-rules`

Use the analysis sections above, plus an ordered action history.

```json
{
  "action": "delete_rule",
  "reason": "duplicate",
  "store": "local",
  "ruleId": "a-rule-id",
  "decision": "approved",
  "approvalSource": "prompt",
  "outcome": "succeeded",
  "error": null
}
```

Record:

- Duplicate deletion and which rule was selected to keep.
- Missing-executable deletion.
- Unresolved-owner and missing-local-profile deletion.
- User decisions: yes, no, skip remaining, and approve all.
- Stores skipped because they cannot be modified locally.
- Attempted, successful, failed, and skipped action counts.

Keep findings observed before an action separate from the action outcome. Do not describe a successful API return as a fresh post-cleanup inventory unless the tool actually re-enumerates.

### `-analyze-inbound-rules`

For each store, preserve the existing four classifications:

`private_only`, `includes_domain`, `includes_public`, `equivalent_to_public`.

Each group contains:

- Total, enabled, disabled, allow, allow-bypass, and block counts as currently reported.
- Counts targeting applications, System, services, neither application nor service, and individual users.
- Count reclassified because of local-subnet comparison differences.
- Verbose-only rule lists grouped by target category.

The schema must describe that this is an analysis classification, not a rewrite of the rule's configured profiles. Private/Domain rules can be considered equivalent to Public rules under the existing comparison policy.

Preserve comparison-policy explanations as structured metadata or explanatory notes. Disabled inbound-allow rules are included and counted separately.

### `-list-app-packages`

A `packages` array containing:

`name`, structured `version` (`major`, `minor`, `build`, `revision`), `architecture`, `resourceId`, `publisher`, `publisherId`, `fullName`, `fullNameSid`, `familyName`, `familyNameSid`.

All are currently printed without requiring `-verbose`.

SID derivation failures must be distinguishable from an empty identifier. Package enumeration failure must not produce a successful empty inventory.

### `-analyze-app-package-rules`

This is a package-reference classification, not the missing-package analysis from `-analyze-rules`. It does not group rules by schema version; a rule whose version predates the PFN field is classified as having no PFN.

For each store, export three named categories with counts and verbose-only rule IDs:

1. PFN present.
2. Package SID present without PFN.
3. Package-like rule name without SID/PFN.

Use `packageLikeName` terminology for the heuristic based on names beginning with `@`; do not assert that the name proves package ownership.

### `-enable-shields-up[:profile]` / `-disable-shields-up[:profile]`

Shared `shields_up_change` result:

- Requested enabled state and target profiles.
- Per-profile set attempt, outcome, and error.
- The subsequent firewall-profile configuration currently printed by `ProcessFirewallPolicy()`.

Distinguish `requestedState`, `setOutcome`, and `observedState`. A failed readback is unknown, not false.

### `-analyze-wfp`

The report has related collections and aggregate summaries.

| Collection | Principal fields |
|---|---|
| `callouts` | Key, runtime ID, name, symbolic name, driver name, layer, third-party classification, enabled/disabled referencing-filter counts |
| `sublayers` | Key, display name, weight, classification; verbose filter counts |
| `providers` | Key, display/service name, classification; verbose filter counts |
| `filters` | Selected third-party-callout filter listings: ID, name, layer, sublayer |
| `summary` | Total/third-party object counts; total/disabled/persistent filters; enabled/disabled callout-filter counts; third-party callout-filter counts |
| Verbose breakdowns | Filters per callout, sublayer, and provider; filters without a provider |

Nonverbose JSON contains the selected third-party listings currently printed. `-verbose` adds the broader inventories and breakdowns.

Two safeguards:

- Label third-party classification as the tool's classification, not verified publisher attribution.
- Preserve unresolved references and unavailable driver names explicitly.

Full WFP filter-condition export would be a separate extension, because it is not currently printed. It also cannot safely serialize the current shallow-copied condition values after their enumeration buffers are freed. Any such extension must create owning, typed condition records while the native data is valid.

### `-remove-callouts [-driver <name>]`

Treat this as a mutation-and-restoration report, not just an inventory.

Sections:

`driverSelection`, `candidateDrivers`, `decisions`, `filterActions`, `restoration`, `diagnostics`.

Record each significant stage:

- Driver matching and approval; the supplied driver option currently uses substring matching and bypasses the per-driver prompt.
- Filter lookup.
- Ownership/security operations.
- Deletion attempt and verification.
- Restoration attempt.
- Provider-context investigation.
- Alternative-session restoration attempts.
- Final restoration outcome and any reboot recommendation.

Identify filters by both key and runtime ID. Restoration may assign a different runtime ID; do not imply the original one is permanent.

Alternative-session details should include the session identity, mode, username/display name when reported, API attempted, and outcome, never raw handles.

This path explicitly calls `TerminateProcess`. Report finalization therefore cannot rely solely on destructors or reaching the end of `wmain`.

### `-signal-restore-callouts`

A small `restore_signal` result:

`eventName`, `signalOutcome`, `error`.

It records only the signal operation. It cannot assert that the other process restored its filters.

### `-?`

A `help` result with usage, command descriptions, modifiers, privilege notes, and interaction notes. Generate console help and JSON help from shared definitions to keep them consistent.

Argument-validation failures use structured diagnostics, including the offending arguments and applicable usage information.

## 4. WFP event schema: `-wfp-events`

Use a discriminated event record:

```json
{
  "type": "classify_drop",
  "timestamp": "2026-10-11T01:30:02.123Z",
  "header": {
    "ipVersion": "ipv4",
    "protocol": { "code": 6, "name": "tcp" },
    "localEndpoint": {
      "address": "192.0.2.10",
      "port": 443,
      "scopeId": null
    },
    "remoteEndpoint": {
      "address": "198.51.100.20",
      "port": 50000,
      "scopeId": null
    }
  },
  "details": {
    "direction": "inbound",
    "filterId": "12345",
    "layerId": 44,
    "isLoopback": false
  },
  "context": {},
  "diagnostics": []
}
```

The shared header additionally supports:

Header flags/presence, reauthorization indication, address family, ICMP type/code, application ID, user SID and resolution, package SID, enterprise ID, policy flags, effective name, and local-interface information.

ICMP type/code must not be mislabeled as TCP/UDP ports. Header presence flags remain authoritative; any displayed value without its flag must be marked as unconfirmed.

Every variant currently handled in `WfpEvents.h` gets its own `details` schema:

| Event type | Additional payload |
|---|---|
| `ike_mm_failure` | Error, failure point, flags, keying module, MM state, SA role, authentication method, certificate hash, MM/filter IDs, principal names/group SIDs, provider context |
| `ike_qm_failure` | Error, failure point, keying module, QM state, SA role/traffic type, QM filter ID, MM SA LUID, provider context |
| `ike_em_failure` | Error, failure point, flags, EM state/authentication, certificate hash, identities/group SIDs, MM ID, SA traffic type |
| `classify_drop` / `classify_allow` | Direction, filter/layer IDs, reauthorization reasons, original/current profiles, loopback; drop-specific virtual-switch fields |
| `ipsec_kernel_drop` | Failure status, direction, SPI, filter/layer IDs |
| `ipsec_dos_drop` | IP version, public/internal host addresses, failure status, direction |
| `capability_drop` / `capability_allow` | Capability code/name, filter ID, loopback |
| `classify_drop_mac` | MAC addresses, direction, media/interface/EtherType, NDIS port, VLAN, LUID, classification and virtual-switch fields |
| `lpm_packet_arrival` | SPI |
| `unknown` | Raw event-type code and explicit unsupported-payload status |

Classify-drop context contains the filter name/description, invoked callout, layer, and sublayer currently printed. Local-interface context contains alias, description, LUID, index, GUID, interface type, and tunnel type where available.

Record context-resolution status and collection time: the inventory is collected earlier, so it is not necessarily current at the moment an event arrives.

## 5. TCP/IP event schema: `-tcpip-events`

Use the same event envelope, with ETW provider identity, event ID/version, source timestamp, and a typed payload.

| Currently subscribed event | Fields |
|---|---|
| Transport drop, ID 1214 | Protocol, address family, inbound direction, local/remote endpoints, discard reason |
| Network drop, ID 1215 | Protocol, address family, direction, source/destination addresses, discard reason, interface index |
| Framing drop, ID 1478 | Address family, direction, interface, discard reason |

Reason codes retain both numeric values and symbolic names, with a reason domain distinguishing transport, network, and framing.

The callback also has cases for IDs 1025, 1055-1058, and 1063, but the session does not subscribe to them, so they are never received. Define their payload (SYN attacks, reassembly violations, connection-rate backlog/violations/depth, and land-attack drops), but do not broaden the subscription as part of JSON support.

Preserve existing noise filtering in both outputs. Capture metadata should describe those exclusions so consumers do not mistake the file for all TCP/IP drops. Missing or malformed ETW properties become diagnostics, not strings such as `"<etw-field-not-set>"`.

## 6. Standard JSON and JSON Lines lifecycle

For `-json`, live events are spooled to disk, then assembled into the normal indented report on graceful shutdown. This bounds memory use. Interrupted or failed finalization must be reported explicitly, with recoverable spool data retained.

For `-jsonl`, each line is a complete record:

```jsonl
{"schemaVersion":"1.0","runId":"a-guid","sequence":1,"kind":"capture_started","command":"wfp_events","data":{}}
{"schemaVersion":"1.0","runId":"a-guid","sequence":2,"kind":"event","command":"wfp_events","data":{"type":"classify_drop"}}
{"schemaVersion":"1.0","runId":"a-guid","sequence":3,"kind":"capture_finished","command":"wfp_events","data":{"status":"interrupted"}}
```

Include start, event, diagnostic, and finish records. Complete flushed lines survive abrupt termination; a missing finish record indicates an incomplete capture. Sequence numbers describe recording order, not guaranteed chronological source-event order.

Open the requested destination before executing operations. File failures must be explicit; reporting failures must never prevent restoration of removed filters.

## 7. Implementation sequence

1. Define the contracts: formal JSON Schema Draft 2020-12 definitions, representative fixtures, shared types, and a command/output/verbosity coverage matrix.
2. Add reporting infrastructure: option parsing, UTF-16-to-UTF-8 serialization, structured diagnostics, lifecycle management, and a JSON library suitable for the native build.
3. Implement finite read-only reports: packages, package-rule classification, profile configuration, rule analysis, inbound analysis, and WFP summaries.
4. Implement mutation reporting: cleanup decisions, Shields Up outcomes, signaling, and callout deletion/restoration stages.
5. Implement live captures: owned event records, thread-safe recording, disk spooling, JSON Lines, graceful stop, and explicit callback/write failures.
6. Close coverage gaps: early returns, loader failures, prompts, warnings, unsupported values, and termination paths; update command help and documentation.

Keep collection/analysis, structured reporting, and console rendering separate. Extend the existing collection and analysis paths to pass their already-retrieved values and failures to both renderers; JSON writers must not query WMI/COM, enumerate again, or independently repeat classification. For each output section, produce one semantic record and apply the same verbosity decision to both renderers. Avoid broad reformatting or unrelated changes to analysis behavior.

## 8. Acceptance criteria

The implementation should demonstrate:

- Every command works with `-json`; live commands additionally support `-jsonl`.
- Both verbosity levels preserve console behavior and equivalent file detail.
- Files parse with PowerShell `ConvertFrom-Json` and `jq`, and validate against the schemas.
- Unicode, escaping, unknown enums, absent fields, and 64-bit values round-trip correctly.
- Counts, duplicate membership, top-3/top-10 rankings, and inbound classifications retain their current meaning.
- Access denial and partial enumeration never appear as successful empty inventories.
- Mutation reports distinguish decisions, attempts, successes, failures, and restoration outcomes.
- Ctrl-C and existing termination paths finalize reports where possible.
- File-write failures cannot bypass filter restoration.
- Live captures stay bounded in memory and never silently discard records.

This document is a plan, not an implementation of the feature. The design uses shared typed schemas, command-specific detail projections, matching verbosity, and separate standard-JSON versus streaming lifecycles.

## 9. Worked output reviews

### Review 1: `-analyze-rules` - firewall-profile configuration

Status: approved and implemented for firewall-profile configuration.

The current `-json <path>` implementation exports firewall-profile configuration, per-store rule-status analysis, per-store application analysis, per-store app-package analysis, per-store SID-owner analysis, per-store filter rankings, and per-store duplicate analysis for `-analyze-rules` and `-clean-rules`, and firewall-profile configuration for Shields Up commands, with optional `-verbose`. Until the remaining schemas are implemented, reports are marked `partial` and include a `json_export_incomplete` warning. Other command combinations and `-jsonl` are not yet supported. Example:

```powershell
.\FwDiagnose\x64\Debug\FwDiagnose.exe -analyze-rules -json .\firewall-profiles.json
```

`ProcessFirewallPolicy()` reads each property once and retains its value or diagnostic in a `FirewallProfileData` record. Its existing console rendering and the JSON writer consume that same record, whether or not `-json` is enabled. `ReadShieldsUp()` remains the single COM read of that setting; the JSON module performs no WMI or COM policy reads. Successful console output is preserved; property failures are displayed as unavailable and collection continues, consistently in both output modes.

The implementation uses the existing C++/WinRT dependency's `Windows.Data.Json` serializer for JSON escaping and a formatting pass to keep `code`/`state` objects on one line. The file is UTF-8 without a BOM.

Focused checks are in `tests\ProfileJsonReportTests.cpp`, built by the `ProfileJsonReportTests` project in the solution. They serialize synthetic collected records, including supplied failures, without reading or writing system firewall configuration. After building the solution, run them from the repository root. The optional argument keeps the generated report; without it, a temporary file is used and deleted:

```powershell
.\x64\Debug\ProfileJsonReportTests.exe .\x64\Debug\profile-failures.json
```

This is the first section of `-analyze-rules`, collected by `ProcessFirewallPolicy()`. Its content is identical with and without `-verbose`. The values below are illustrative, not captured from a running executable.

#### Console output

```text
Firewall Policies for profile: Public
    Enabled: 1
    Shield's Up (block all inbound traffic): Disabled
    Default Inbound Action: Block
    Default Outbound Action: Allow
    Allow Inbound Rules: True
    Allow Local Firewall Rules: Not Configured
    Allow User Apps: False
    Allow User Ports: Not Configured
    Allow Unicast Response To Multicast: True
    Disabled Interface Aliases:
    Test Adapter
```

#### Proposed JSON

The following is one element of `results[].data.firewallProfiles`.

```json
{
  "profile": "public",
  "displayName": "Public",
  "policyStore": "ActiveStore",
  "enabled": { "code": 1, "state": "true" },
  "defaultInboundAction": { "code": 4, "state": "block" },
  "defaultOutboundAction": { "code": 2, "state": "allow" },
  "blockAllInboundTraffic": {
    "friendlyName": "Shields-Up",
    "value": false
  },
  "allowUserApps": { "code": 0, "state": "false" },
  "allowUnicastResponseToMulticast": { "code": 1, "state": "true" },
  "allowLocalFirewallRules": { "code": 2, "state": "not_configured" },
  "allowInboundRules": { "code": 1, "state": "true" },
  "allowUserPorts": { "code": 2, "state": "not_configured" },
  "disabledInterfaceAliases": ["Test Adapter"],
  "status": "completed",
  "diagnostics": []
}
```

JSON permits whitespace and newlines between tokens. Keeping `code` and `state` on the same line preserves valid JSON and makes short value objects easier to scan. The JSON renderer explicitly emits firewall-profile properties in the order above, rather than relying on the JSON library's object iteration order. Additional future properties are retained after these fields; consumers should still treat JSON objects as unordered.

#### Mapping and interpretation

- Every console field has a corresponding JSON property.
- Configurable booleans preserve `not_configured`; they cannot safely become plain booleans.
- Named states are readable without Windows API knowledge; raw codes preserve unknown future values.
- `blockAllInboundTraffic.friendlyName` gives the setting the recognizable label `Shields-Up`, while `value` remains a real JSON boolean.
- Disabled interfaces are an array. A successfully read empty collection is `[]`, not `"None"`.
- `ActiveStore` identifies the policy source. It does not mean Public is the currently connected network's profile; the command enumerates profile configurations.

#### Purpose of diagnostics

Profile-level `diagnostics` records problems collecting that profile's values, not findings about firewall-rule configuration. Examples include a failed COM property read, an unrecognized policy value, or an interface-alias read failure. `[]` means no such problems were recorded.

Any property-read failure is recorded, and collection continues with the remaining properties. Failed coded values use `{ "code": null, "state": "unavailable" }`; failed string, boolean, and array values use `null`. A successful null/empty `DisabledInterfaceAliases` value is the documented no-disabled-interfaces case and becomes `[]`, not a failure. Successfully read `not_configured` values do not produce diagnostics. Unknown numeric values retain their code and produce a warning. The profile's `status` is `partial` if it has diagnostics, otherwise `completed`.

Diagnostics belong at the narrowest relevant scope. A property-read problem belongs on its profile; a whole-command failure belongs on its command result. Avoid repeating the same diagnostic at every scope.

For example, if the Shields Up read fails, export an unknown value instead of falsely reporting that the setting is disabled:

```json
{
  "blockAllInboundTraffic": {
    "friendlyName": "Shields-Up",
    "value": null
  },
  "diagnostics": [
    {
      "severity": "error",
      "code": "policy_property_read_failed",
      "message": "Could not read the Shields-Up setting.",
      "operation": "INetFwPolicy2::get_BlockAllInboundTraffic",
      "subject": {
        "profile": "public",
        "property": "blockAllInboundTraffic"
      },
      "error": {
        "domain": "hresult",
        "code": 2147942405,
        "hex": "0x80070005"
      }
    }
  ]
}
```

This error example is illustrative. The implementation must capture the actual API error rather than substituting a fixed code.

### Review 2: `-analyze-rules` - rule-status analysis per policy store

Status: approved and implemented.

`CheckForRulesWithErrorStatus()` reports rule-status categories independently for each store. The following values are illustrative.

#### Console without `-verbose`

```text
  * Summary of status analysis of firewall rules:
   - count of rules with no errors: 4 (out of a total of 5 rules)
   - count of rules with parsing errors: 1
```

#### Proposed JSON without `-verbose`

The following is a store record within `results[].data.stores`:

```json
{
  "store": "local",
  "displayName": "Local",
  "ruleDetails": {
    "totalRuleCount": 5,
    "errorRuleCount": 1,
    "categories": [
      { "category": "parsing_error", "count": 1 }
    ]
  },
  "status": "completed",
  "diagnostics": []
}
```

The store's `status` describes collection/processing, not whether its rules have error statuses. Rule-status findings belong in `ruleDetails`; collection failures belong in `diagnostics`. Format analyzed stores as `store`, `displayName`, `ruleDetails`, `status`, then `diagnostics`.

#### Console with `-verbose`

```text
  * Summary of status analysis of firewall rules:
   - count of rules with no errors: 4 (out of a total of 5 rules)
   - count of rules with partially ignored (some fields not understood): 0
   - count of rules with completely ignored (newer schema with unknown fields): 0
   - count of rules with parsing errors: 1
       A rule has parsing error (0x00080003):  Rule Name:  Example App
   - count of rules with semantic errors: 0
   - count of rules with runtime errors: 0
   - count of rules with unknown errors: 0
```

#### Proposed JSON with `-verbose`

```json
{
  "store": "local",
  "displayName": "Local",
  "ruleDetails": {
    "totalRuleCount": 5,
    "errorRuleCount": 1,
    "categories": [
      {
        "category": "parsing_error",
        "count": 1,
        "rules": [
          {
            "ruleId": "example-rule-id",
            "name": "Example App",
            "status": { "code": 524291, "state": "parsing_error" },
            "statusHex": "0x00080003"
          }
        ]
      }
    ]
  },
  "status": "completed",
  "diagnostics": []
}
```

The example status code is `FW_RULE_STATUS_PARSING_ERROR_APP`, retaining the specific raw status while classifying it under the same broad parsing-error category as the console.

- Without `-verbose`, include only nonzero error categories and omit their `rules` arrays, matching the console's compact summary.
- When `errorRuleCount` is zero, write `categories: []` at both verbosity levels rather than six zero-count entries. Keep the array present for a consistent structure; schemas must allow it to be empty.
- With `-verbose`, also include only nonzero error categories, adding their affected-rule arrays. Format category properties as `category`, `count`, then `rules`; do not add an inventory of error-free rules. Console output retains its existing verbose zero-count summaries.
- Preserve the existing status classification order. Each rule is assigned to one category.
- Each named category owns its JSON name and collected rule pointers together. Classification uses named members; serialization iterates those records without parallel name arrays or numeric category indices.
- `errorRuleCount` is the total minus the existing analysis's no-error count, equal to the sum of all six error-category counts, including partially and completely ignored rules. Console output retains its existing no-error summary.
- Format `ruleDetails` properties as `totalRuleCount`, `errorRuleCount`, then `categories`.
- Include the rule ID as stable identity even when the console uses its name; names need not be unique.
- A successfully empty store has zero rules, not a collection failure. The existing "No Rules in this store" output is represented at store scope rather than inventing an analysis that did not run.

Store collection outcomes are retained during firewall enumeration. Successfully empty stores contain `status: "completed"` and `ruleCount: 0`, without `ruleDetails`. Missing stores use `not_present`; unattempted stores use `not_collected`; Other collection errors use `failed`. These unavailable-store records include the collection error in `diagnostics`, rather than reporting zero rules, except that `ERROR_FILE_NOT_FOUND` for `group_policy_rsop` is expected: retain its identity and `status: "not_present"` without `diagnostics`, `ruleCount`, or `ruleDetails`, at both verbosity levels. Other RSOP failures still include diagnostics. Under `-clean-rules`, a read-only store that loaded with rules uses `skipped` with `reason: "store_cannot_be_modified_locally"`; a read-only store that loaded empty is `completed` with `ruleCount: 0`, and one that failed to load keeps its load status.

### Review 3: `-analyze-rules` - application analysis per policy store

Status: approved and implemented.

`CheckForMissingAppRules()` builds one analysis per store; the console and JSON are both written from it. The following values are illustrative.

#### Console with `-verbose`

```text
  * Summary of application analysis of firewall rules:
   - count of rules with an application exe: 479
   - count of rules with an application exe referencing non-existing file: 2
     - of those, using a per-user environment variable (the Firewall service resolves it as LocalService): 1
   - WARNING: count of rules with an application exe using %USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%, or %TMP% (resolves within the profile of the Firewall service account): 1
     WARNING: Application-exe:  '%APPDATA%\app.exe'  [Rule Name:  Service rule]
   - rules with an application exe referencing non-existing file:
     Application-exe:  '%HOMEPATH%\app.exe' (per-user environment variable)  (Contains per-user environment variable) [Rule Name:  Per-user rule]
     Application-exe:  'C:\missing\app.exe'  (Failed to find the file (0x80070003)) [(no Rule Name) RuleId:  missing-rule]
```

The last heading previously read "unique rule names of rules with ..."; it lists every rule, so "unique rule names" was removed.

#### JSON with `-verbose`

`applicationAnalysis` is added to the store record after `ruleDetails`:

```json
"applicationAnalysis": {
  "status": "completed",
  "applicationRuleCount": 479,
  "missingApplicationRuleCount": 2,
  "perUserVariableRuleCount": 1,
  "serviceProfileVariableRuleCount": 1,
  "serviceProfileVariableRules": [
    { "ruleId": "service-rule", "name": "Service rule", "application": "%APPDATA%\\app.exe" }
  ],
  "missingApplicationRules": [
    {
      "ruleId": "per-user-rule",
      "name": "Per-user rule",
      "application": "%HOMEPATH%\\app.exe",
      "reason": "per_user_environment_variable"
    },
    {
      "ruleId": "missing-rule",
      "name": null,
      "application": "C:\\missing\\app.exe",
      "reason": "file_lookup_failed",
      "error": { "domain": "hresult", "code": 2147942403, "hex": "0x80070003" }
    }
  ]
}
```

- `applicationAnalysis` is present for every store whose rules were analyzed, even when all counts are zero. Empty, absent, failed, and skipped stores do not have it.
- Without `-verbose`, `missingApplicationRules` is omitted. `serviceProfileVariableRules` is present at both verbosity levels, matching the console's warnings, which always print.
- `missingApplicationRuleCount` counts every rule whose file was reported missing: a per-user environment variable, or any `FindFirstFileExW` failure. `perUserVariableRuleCount` is the subset with a per-user variable.
- `reason` is `per_user_environment_variable` (no file lookup, so no `error`) or `file_lookup_failed` with the lookup's `error`, converted with `HRESULT_FROM_WIN32`.
- Service-profile-variable rules (`%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%TMP%`) are warnings: they are not looked up and are never counted as missing.
- Every rule is listed; nothing is de-duplicated. `ruleId` and `name` are `null` when absent.
- A 32-bit build on 64-bit Windows does not look up files: `status` is `skipped` with `reason: "wow64_redirection"`. Rules with a per-user variable are still counted as missing because that check needs no lookup.
- Field order: `status`, `reason`, `applicationRuleCount`, `missingApplicationRuleCount`, `perUserVariableRuleCount`, `serviceProfileVariableRuleCount`, `serviceProfileVariableRules`, `missingApplicationRules`. Rule entries: `ruleId`, `name`, `application`, `reason`, `error`. Error objects everywhere: `domain`, `code`, `hex`.

### Review 4: `-analyze-rules` - app-package analysis per policy store

Status: approved and implemented.

`CheckForMissingAppPackage()` builds one analysis per store with `AnalyzePackageRules()`; the console and JSON are both written from it. The following values are illustrative.

#### Console with `-verbose`

```text
  * Summary of app-package analysis of firewall rules:
   - count of rules with a package ID: 2
   - count of rules with a package ID referencing a non-existing package: 1
   - count of rules with a package family name: 941
   - count of rules with a package family name referencing a non-existing package: 2
   - rules referencing a non-existing package:
     Package-ID:  'S-1-15-2-999'  [Rule Name:  both rule]
     Package-Family-Name:  'Missing.App_x'  [Rule Name:  both rule]
     Package-Family-Name:  'Missing.App_x'  [(no Rule Name) RuleId:  family-rule]
```

The list heading previously read "unique rule names of rules with a package ID referencing a non-existing package"; it lists every missing reference, including package family names, so it was renamed. If the installed packages could not be loaded, the console prints only `  * Skipping the app-package analysis: installed packages could not be loaded (0x80070005)`, with the code in 8-digit form.

#### JSON with `-verbose`

`packageAnalysis` is added to the store record after `applicationAnalysis`:

```json
"packageAnalysis": {
  "status": "completed",
  "packageIdRuleCount": 2,
  "missingPackageIdRuleCount": 1,
  "packageFamilyNameRuleCount": 941,
  "missingPackageFamilyNameRuleCount": 2,
  "missingPackageIdRules": [
    { "ruleId": "both-rule", "name": "Both rule", "packageId": "S-1-15-2-999" }
  ],
  "missingPackageFamilyNameRules": [
    { "ruleId": "both-rule", "name": "Both rule", "packageFamilyName": "Missing.App_x" },
    { "ruleId": "family-rule", "name": null, "packageFamilyName": "Missing.App_x" }
  ]
}
```

- `packageAnalysis` is present for every store whose rules were analyzed, even when all counts are zero.
- Without `-verbose`, both lists are omitted.
- A rule missing both references appears in both lists. `ruleId`, `name`, and the package are `null` when absent.
- Only non-empty references are counted. A 2.27 rule cannot carry a package family name, so it is never counted as having one.
- If the installed packages could not be loaded, no rule is checked: `status` is `failed`, there are no counts or lists, and `diagnostics` has one entry with `code: "app_packages_not_loaded"`, `operation: "load_app_packages"`, and the load `error`.
- Field order: `status`, `packageIdRuleCount`, `missingPackageIdRuleCount`, `packageFamilyNameRuleCount`, `missingPackageFamilyNameRuleCount`, `missingPackageIdRules`, `missingPackageFamilyNameRules`, `diagnostics`. Rule entries in every analysis: `ruleId`, `name`, `application`, `packageId`, `packageFamilyName`, `reason`, `status`, `statusHex`, `error`. This also fixes the order of rule-status entries, which was previously arbitrary.

### Review 5: `-analyze-rules` - SID-owner analysis per policy store

Status: approved and implemented.

`CheckUnresolvedUserAccountRules()` builds one analysis per store with `AnalyzeUserOwnerRules()`; the console and JSON are both written from it. The following values are illustrative.

#### Console with `-verbose`

```text
  * Summary of SID owner analysis of firewall rules:
   - count of rules with LocalUserOwner SID: 3690
   - count of rules with LocalUserOwner SID referencing unresolved SID: 2
   - count of rules with LocalUserOwner SID referencing non-existing local profile: 2
   - rules with unresolved SIDs:
     Unresolved SID:  'not-a-sid'  (Failed to convert string SID to SID (0x80070539))  [Rule Name:  bad sid rule]
     Unresolved SID:  'S-1-5-21-1-2-3-1001'  (Failed to lookup account SID (0x80070534))  [(no Rule Name) RuleId:  unknown-rule]
   - rules with no local profile:
     SID:  'S-1-5-21-1-2-3-1002' (CONTOSO\alice)  [Rule Name:  no profile rule]
     SID:  'S-1-5-21-1-2-3-1003' (bob)  [(no Rule Name) RuleId:  no-domain-rule]
```

- Failure codes print in 8-digit form, and the failure text no longer has padding spaces. The `-clean-rules` deletion prompt uses the same text.
- List headings are indented like the counts, and each missing-profile finding is on one line. The domain is omitted when the account has none.
- The local-profile count prints only for stores where the check ran (Application-Isolation and Interface-Isolation).
- Without `-verbose`, the summary prints only when something was found.
- If the local profiles could not be read, the console prints `  * Skipping the local-profile check: local profiles could not be read (0x80070005)` and the run continues; previously the error ended the run. Unresolved owners are still reported.

#### JSON with `-verbose`

`userOwnerAnalysis` is added to the store record after `packageAnalysis`:

```json
"userOwnerAnalysis": {
  "status": "completed",
  "localUserOwnerRuleCount": 3690,
  "unresolvedSidRuleCount": 2,
  "localProfileCheck": "completed",
  "missingLocalProfileRuleCount": 2,
  "unresolvedSidRules": [
    {
      "ruleId": "bad-sid-rule",
      "name": "Bad SID rule",
      "localUserOwnerSid": "not-a-sid",
      "reason": "invalid_sid_string",
      "error": { "domain": "hresult", "code": 2147943737, "hex": "0x80070539" }
    },
    {
      "ruleId": "unknown-rule",
      "name": null,
      "localUserOwnerSid": "S-1-5-21-1-2-3-1001",
      "reason": "account_lookup_failed",
      "error": { "domain": "hresult", "code": 2147943732, "hex": "0x80070534" }
    }
  ],
  "missingLocalProfileRules": [
    { "ruleId": "no-profile-rule", "name": "No profile rule", "localUserOwnerSid": "S-1-5-21-1-2-3-1002", "domain": "CONTOSO", "user": "alice" },
    { "ruleId": "no-domain-rule", "name": null, "localUserOwnerSid": "S-1-5-21-1-2-3-1003", "domain": "", "user": "bob" }
  ]
}
```

- `userOwnerAnalysis` is present for every store whose rules were analyzed, even when all counts are zero.
- Without `-verbose`, both lists are omitted.
- `localProfileCheck` is `completed`, `not_applicable` (stores other than Application-Isolation and Interface-Isolation), or `failed`. `missingLocalProfileRuleCount` is present only when it is `completed`.
- If the local profiles could not be read, `status` is `partial`, `localProfileCheck` is `failed`, and `diagnostics` has one entry with `code: "local_profiles_not_read"`, `operation: "read_profile_list"`, `subject.property: "localProfiles"`, and the read `error`. The unresolved-SID count and list are still present.
- `ruleId`, `name`, `localUserOwnerSid`, `domain`, and `user` are `null` when absent. An account without a domain has `domain: ""`.
- Field order: `status`, `localUserOwnerRuleCount`, `unresolvedSidRuleCount`, `localProfileCheck`, `missingLocalProfileRuleCount`, `unresolvedSidRules`, `missingLocalProfileRules`, `diagnostics`. Rule entries in every analysis: `ruleId`, `name`, `application`, `packageId`, `packageFamilyName`, `localUserOwnerSid`, `domain`, `user`, `reason`, `status`, `statusHex`, `error`.

### Review 6: `-analyze-rules` - filter rankings per policy store

Status: approved and implemented.

`RankRulesByFilterCounts()` builds one ranking per store with `AnalyzeFilterRankings()`; the console and JSON are both written from it. Rules are grouped by normalized (lowercase) name, and filters are counted once per name across every WFP filter on the machine, so the counts are not limited to the store being analyzed.

#### Console

```text
  * Top 3 rule names by WFP filter count:
    [396 filters] 'microsoft edge (mdns-in)'  [33 rules match this name]
    [192 filters] 'microsoft teams'  [20 rules match this name]
    [108 filters] 'game bar'  [6 rules match this name]

  * Top 3 rule names by WFP filter-condition count:
    [2180 conditions] 'microsoft media foundation network source in [tcp 554]'
    [1527 conditions] 'cast to device streaming server (rtsp-streaming-in)'  [3 rules match this name]
    [1452 conditions] 'microsoft edge (mdns-in)'  [33 rules match this name]
```

- `-verbose` raises the limit from 3 to 10 rule names.
- Ties are ordered by name. Previously the order was arbitrary, and counts were computed twice; the second computation skipped the last name, which could list a name twice.
- Rule names without filters (or without filter conditions) are not ranked, and a ranking with no entries is not printed.
- `[N rules match this name]` prints only when more than one rule has the name.
- If the WFP filters could not be read, the console prints `  * Skipping the filter rankings: WFP filters could not be read (0x80070005)` instead of empty rankings, and the failure is recorded in the exit code.

#### JSON with `-verbose`

`filterRankings` is added to the store record after `userOwnerAnalysis`:

```json
"filterRankings": {
  "status": "completed",
  "correlationMethod": "rule_name",
  "filterScope": "all_wfp_filters",
  "limit": 10,
  "byFilterCount": [
    {
      "ruleName": "microsoft edge (mdns-in)",
      "ruleCount": 33,
      "filterCount": 396,
      "filterConditionCount": 1452,
      "ruleIds": ["{AE310CFB-588A-46B6-8977-F3F2D55D82CC}", "..."]
    }
  ],
  "byFilterConditionCount": [
    {
      "ruleName": "microsoft media foundation network source in [tcp 554]",
      "ruleCount": 1,
      "filterCount": 30,
      "filterConditionCount": 2180,
      "ruleIds": ["..."]
    }
  ]
}
```

- `filterRankings` is present for every store whose rules were analyzed; the lists are empty when no rule name has filters.
- The lists hold the same entries as the console, up to `limit`. Each entry has both counts, whichever list it is in.
- `ruleName` is the normalized name that filters were matched on, as printed by the console.
- Without `-verbose`, `ruleIds` is omitted. A rule without an ID has a `null` entry.
- If the WFP filters could not be read, `status` is `failed`, `limit` and both lists are omitted, and `diagnostics` has one entry with `code: "wfp_filters_not_loaded"`, `operation: "enumerate_wfp_filters"`, `subject.property: "wfpFilters"`, and the read `error`.
- Field order: `status`, `correlationMethod`, `filterScope`, `limit`, `byFilterCount`, `byFilterConditionCount`, `diagnostics`. Entries: `ruleName`, `ruleCount`, `filterCount`, `filterConditionCount`, `ruleIds`.

### Review 7: `-analyze-rules` - duplicate analysis per policy store

Status: approved and implemented.

`AnalyzeDuplicateRules()` finds the sets of duplicate rules in one store; the console and JSON are both written from it, and `-clean-rules` deletes from the same sets. Rules are duplicates when they match on every setting except the rule ID, name, description, and schema version. Profiles and the active flag are compared, so rules differing only in either are not duplicates.

#### Console

```text
  * Summary of duplicate analysis of firewall rules:
   - count of sets of duplicate rules: 3
   - count of rules in sets of duplicate rules: 6
   - sets of duplicate rules:
       [2 rules] (no Rule Name) RuleId:  {d5}  (Application-exe: '%SystemRoot%\System32\svchost.exe')
       [2 rules] Rule Name:  another  [2 different names]
       [2 rules] Rule Name:  zz
```

- Without `-verbose`, only the two counts print, and nothing prints when a store has no duplicates.
- Sets are ordered alphabetically by the name of their first rule; rules within a set are ordered by name, then by rule ID (rules without a name or ID first). Previously sets were in comparison order.
- A set's first rule is printed: its name, or its rule ID if it has no name, and its application if any.
- `[N different names]` prints when the rules of a set have more than one (case-insensitive) name.

#### JSON with `-verbose`

`duplicateAnalysis` is added to the store record after `filterRankings`:

```json
"duplicateAnalysis": {
  "status": "completed",
  "ignoredFields": ["ruleId", "name", "description", "schemaVersion"],
  "duplicateSetCount": 1,
  "duplicateRuleCount": 2,
  "duplicateSets": [
    {
      "ruleCount": 2,
      "application": null,
      "rules": [
        { "ruleId": "MDEServer-1", "name": null },
        { "ruleId": "WMPNetworkSvc-2", "name": null }
      ]
    }
  ]
}
```

- `duplicateAnalysis` is present for every store whose rules were analyzed, with zero counts when there are no duplicates.
- `ignoredFields` lists the fields that are not compared, so a reader knows why rules in a set can have different names.
- `duplicateRuleCount` counts every rule in every set, including the one rule per set that `-clean-rules` keeps.
- Without `-verbose`, `duplicateSets` is omitted. With `-verbose`, it is present and empty when there are no duplicates.
- Sets and their rules are in console order. `name` keeps its original case, unlike the console. `application` is the set's shared application, or `null` when the rules have none. `ruleId` and `name` are `null` when absent.
- Field order: `status`, `ignoredFields`, `duplicateSetCount`, `duplicateRuleCount`, `duplicateSets`. Sets: `ruleCount`, `application`, `rules`. Rules: `ruleId`, `name`.
