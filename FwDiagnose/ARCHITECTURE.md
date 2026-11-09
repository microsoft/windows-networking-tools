# FwDiagnose architecture

FwDiagnose is a single-process C++ console application. It takes a snapshot of system state into in-memory global collections, then runs analyses over those snapshots and prints the results. It has no service, no persisted state, and no shared repository library beyond the header-only wrappers in `ctl/`.

## Modules

| File | Responsibility |
|---|---|
| `FwDiagnose.cpp` | `wmain`, argument parsing, loader threads, command dispatch. Holds option flags as globals behind accessors declared in `FwDiagnose.h`. |
| `FwDiagnose.h` | Option accessors, `GuidToString`, deletion prompts, `ChronoTimer`. |
| `firewall.h` | Declarations for the undocumented-in-SDK `FW_*` types and functions from `FirewallAPI.dll`. |
| `FirewallRules.*` | Loads rules from all stores; all rule analyses and deletion; profile policy; Shields Up. |
| `NormalizedFirewallRule.*` | Canonical per-rule record and comparison functions. |
| `NormalizedString.h` | Case-insensitive string with an ASCII fast path. |
| `AppContainers.*` | Installed-package inventory and SID derivation. |
| `WfpCounters.*` | Shared WFP engine handle, layer names and ordering, shared WFP types. |
| `WfpCallouts.cpp` | Callout inventory, built-in list, driver names from ETW, filter removal and restoration. |
| `WfpFilters.cpp`, `WfpSublayers.cpp`, `WfpProviders.cpp` | Inventories, lookups, built-in lists, and printing. |
| `WfpOutput.cpp` | `-analyze-wfp` report. |
| `WfpEvents.*` | `-wfp-events` subscription and event formatting. |
| `TcpipEvents.*` | `-tcpip-events` ETW session, noise filtering, and discard-reason names. |
| `WilNetworkLocal.h` | Temporary `ResetCompleteAddressNothrow`, until `socket_address::reset_complete_address_nothrow` is published in `wil/network.h`. |
| `IpProperties.*` | Interface and unicast-address snapshot, used to annotate WFP events. |
| `ProfileJsonReport.*` | `-json` report. |
| `tests/ProfileJsonReportTests.cpp` | Standalone JSON checks; not part of the project or solution. |

## Execution flow

```text
wmain
  CoInitializeEx (multithreaded), extract -json, init report
  RunFwDiagnose
    parse arguments: each option is found, removed, and sets a global
    early exits: -?, -signal-restore-callouts,
                 -list-app-packages, -analyze-app-package-rules
    anything left over -> error

    load phase (threads)
      wfp:      callouts -> sublayers -> providers -> filters -> counts and sorts
      firewall: all policy stores
      packages: installed packages
      network:  interfaces and addresses
      (-remove-callouts joins wfp only, runs, and returns)

    analysis phase (main thread, fixed order)
      policy + rules -> inbound -> shields -> WFP report -> WFP events -> TCP/IP events
  FinishProfileJsonReport
```

The loader functions are `noexcept` or catch at their boundary, and print failures. Firewall stores and app packages record their load result, and the analyses report a failure rather than treating the data as empty. A failed WFP or IP load still looks like an empty collection to later stages. Worker threads make WinRT and COM calls using the process-wide multithreaded apartment created in `wmain`.

The load phase runs for every non-early-exit command, even ones that need only part of the data, such as Shields Up.

## Data model

Each inventory is a file-scope global, written by one loader thread and treated as read-only by the main thread after the joins.

| Global | Type | Notes |
|---|---|---|
| `g_policy_objects` | `FirewallPolicyObjects[10]` | One per store, in fixed order. |
| `g_all_filters` | `vector<FilterDetails>` | Sort order changes during a run. |
| `g_all_callouts` | `vector<CalloutDetails>` | Driver names merged from ETW. |
| `g_all_sublayers`, providers | Vectors | Counts updated while filters load. |
| `g_app_packages` | `vector<AppContainerPackage>` | |
| `g_ip_details` | `vector<IpInterfaceDetails>` | |

The ten stores are Local, Group Policy, RSOP, static and configurable Windows Service Hardening, static and dynamic Interface Isolation, Application Isolation, MDM, and Tenant Restrictions. A store that does not exist (`ERROR_FILE_NOT_FOUND`) has no rules. A store that fails for any other reason is reported as not analyzed, and the remaining stores still load.

### Firewall rule access

The firewall APIs are resolved at runtime from `FirewallAPI.dll`. Each store is opened at the newest supported schema version: 2.33, then 2.31, then 2.27.

`FW_RULE` allocations are laid out according to the **requested** version, so a field is safe to read only if both the requested version and the rule's `wSchemaVersion` support it. `NormalizedFirewallRule` stores the requested version for this reason.

Rule memory from `FWEnumFirewallRules` is intentionally never freed. `NormalizedFirewallRule::fw_rule` points into it for the life of the process, and it remains valid after the store is closed.

Each `FirewallPolicyObjects` holds its store handle, which stays open until the process exits. `-clean-rules` deletes rules through the handle of the store being cleaned. RSOP and static Windows Service Hardening deny read/write access even to Administrators, so they are always opened read-only and only reported on.

A rule's application file is checked only when the result is meaningful: `System` and packaged apps are skipped, and only "file not found" or "path not found" counts as missing. A path using a per-user variable such as `%HOMEPATH%` is treated as broken without a file lookup, because the Firewall service (`mpssvc`) resolves rule paths as LocalService rather than as the user. A path using `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, or `%TMP%` resolves within that account's profile, which may be deliberate, so it is reported as a warning and is never a deletion candidate. A 32-bit process on 64-bit Windows does not look up files at all, because file system and environment redirection would make existing files look missing.

### Rule normalization and comparison

`NormalizedFirewallRule` resolves `@file,-id` resource strings in names and descriptions, then builds `normalized_rule_details`, a comma-separated string of the rule's semantic fields.

Comparison (`RuleDetailsComparison`) has separate steps so that a `ComparisonPolicy` can relax them:

| Step | Policy flag that relaxes it |
|---|---|
| `dwProfiles` | `skip_comparing_profiles` |
| `wFlags` | `skip_comparing_if_enabled` (ignores only the active flag) |
| Address keywords | `skip_comparing_local_subnet` (ignores only Local Subnet) |
| `normalized_rule_details` | None |

The rule ID, name, description, and schema version are **excluded**, which is why duplicates can have different names and why deletion may ask which to keep. Status and origin are included, so otherwise identical rules with different statuses are not duplicates.

`NormalizedString` lowercases ASCII until the first non-ASCII character, then compares with `memcmp` when both strings are ASCII and with `CompareStringOrdinal` otherwise. Two consequences: strings of different length never compare equal, and printed rule and filter names appear in lowercase because the normalized text is what gets displayed. Use `fw_rule->wszName` when the original spelling matters, as the JSON report does.

### Rules and filters

The only link from a firewall rule to its WFP filters is the display name, so filter counts are by name and not exact. Several rules with one name share one count, stored on the last rule in that name's run, and `duplicate_rule_count` records how many share it.

### WFP notes

- `GetFwpmEngineHandle` lazily opens one shared engine handle under a lock, and it is never closed.
- `FilterDetails::filterConditions` is a **shallow** copy; its pointers are invalid once the enumeration buffer is freed. Only `numFilterConditions` is safe. A condition export must deep-copy while the native data is valid.
- Driver names are not available from `FwpmCalloutEnum0`. `LoadWfpCallouts` gets them from a one-second ETW rundown of provider `{00e7ee66-5b24-5c41-22cb-af98f63e2f90}`.
- Third-party status means the key is absent from the `BuiltIn*` GUID arrays. Add newly identified Windows GUIDs there and in the matching `*ToString` function. `BuiltInCalloutsToString` fails fast on a GUID missing from its chain.

## Callout removal

`TemporarilyRemoveWfpCalloutFilters` works in these stages:

1. Build the list of third-party drivers, filtered by `-driver` if given.
2. Install a console control handler, so an interruption at any later point restores what was deleted.
3. Prompt per driver, unless `-driver` was given.
4. For each matching filter: fetch the full filter, fetch its original owner, group, and DACL, take ownership, delete by key, and confirm that it is gone. If the filter is not deleted, its original security is put back. Save the filter and descriptor to `g_deletedWfpFilters`. `g_deletedWfpFiltersLock` is held across this step, and the control handler takes it and never releases it, so a filter being deleted is recorded and restored, and no further deletions start.
5. Start a thread waiting for Enter, and create the named event.
6. Wait for either signal, restore, and call `TerminateProcess`. Every restore path holds `g_deletedWfpFiltersLock`, so filters are only restored once.

`TerminateProcess` is deliberate: the Enter thread may still be blocked in `getline`, which breaks CRT shutdown. Anything that must happen at exit on this path has to happen before that call, which matters for future JSON reporting.

Restoration uses `FwpmFilterAdd0` with the original security descriptor. If that fails, it retries with default security and prints a warning, because getting the filter back matters more than its security. The SACL is not preserved. A restored filter keeps its key but may get a new runtime ID. On `FWP_E_WRONG_SESSION`, it tries again through each active WFP session.

## Design rules

- Collect once, then render. Printing and JSON take the same collected record (see `FirewallProfileData`); JSON code must not query the system itself.
- Preserve the difference between "not configured", "false", and "could not read". `FirewallProfileData` uses `std::optional` for this.
- Print all error codes as base-16 with a `0x` prefix. Convert Win32 (`DWORD`) error codes with `HRESULT_FROM_WIN32` before printing, and print `NTSTATUS` codes unconverted. Convert every error from `Fwpm*` and `Fwps*` functions the same way: those APIs can return either kind of code, and `HRESULT_FROM_WIN32` leaves an existing `HRESULT` unchanged.
- Keep the semantics of the comparison policies when changing duplicate or inbound grouping.
- Respect the requested-version rule when adding `FW_RULE` fields.
- Prefer `enum class` to boolean parameters and explicit `.has_value()`. The remaining conventions are in `.github/copilot-instructions.md`.

## Testing

The solution includes two test projects in `tests/`. `NormalizedStringTests` covers `StrStrComparison`. `ProfileJsonReportTests` includes `ProfileJsonReport.cpp` directly and checks the JSON report using synthetic data. Neither needs system access. Run them from the build output, or set one as the startup project in Visual Studio; the exit code is nonzero if a test fails:

```powershell
msbuild WindowsNetworkingTools.sln /m /p:Configuration=Debug /p:Platform=x64
.\x64\Debug\NormalizedStringTests.exe
.\x64\Debug\ProfileJsonReportTests.exe
```

Otherwise, the safe smoke test is `FwDiagnose.exe -?`, which exits before loading any data. Other commands depend on the machine's state, and the mutating ones need a test machine.

## Known issues

Found by reading the code at commit `a1118bb`; none were reproduced by running the tool.

### High impact

| Issue | Location | Effect |
|---|---|---|
| A crash or forced kill strands removed filters | `TemporarilyRemoveWfpCalloutFilters` | The saved filters exist only in this process's memory, so they cannot be restored if it ends without running its console control handler. |

### Medium impact

| Issue | Location | Effect |
|---|---|---|
| Framing drops fall through | `ListenForTcpipEvents` | The `TcpipFramingPacketDrops` case has no `break`, so each framing event also prints a "Failed to read 'SynAttacksDetected'" message. |
| Allow-bypass counts corrupt | `InboundRuleGroup::swap_rule_counts` | A missing `else` makes bypass rules also decrement `allow_rule_count`, which underflows. |
| Prompts loop forever at end of input | `PromptForDeletion` | `getline` failure is not checked. Redirected or closed stdin spins indefinitely. |
| Refresh double-counts | `LoadWfpFilters` via `FindFilterByFilterId` | A reload increments sublayer and provider counts without resetting them. |

### Lower impact

| Issue | Location |
|---|---|
| `DebugBreak()` in shipping paths; without a debugger the process crashes, and a C++ `try` does not catch it. | `FindPackageSid`, `FindPackageFamilyName`, `ListenForTcpipEvents`, `NormalizedString::StringCompare` |
| Debug output `<<-->>` left in inbound analysis. | `AnalyzeInboundRules` |
| `wszPackageFamilyName` read without the requested-version guard. | `RuleTargetsLocalNonSystemApplication`, `AnalyzeFirewallRulesReferencingAppPackages` |
| `is_rule_deleted` is set only by the last cleanup phase, so the checks for it in earlier phases never fire. | `Delete*Rules` |
| Unused code: `InitializeWfpPerfCounters` and `ReadWfpPerfCounters` have no callers, and `GetRulesWithAppPackages` is declared but never defined. | `WfpCounters.*`, `FirewallRules.h` |

### Documentation and test drift

- `JSON-OUTPUT-PLAN.md` cites `FirewallRules.cpp:2455` for `ProcessFirewallPolicy`; it has moved to about line 2783.
- The help text says `-analyze-inbound-rules` covers "active" rules, and that `-driver` must follow `-remove-callouts`. Neither matches the code.
