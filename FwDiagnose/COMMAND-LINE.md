# FwDiagnose command line

```text
FwDiagnose.exe [options] [-verbose] [-json <path>]
```

Option names are case-insensitive and use a single leading `-`. With no arguments, the tool prints usage and returns `E_INVALIDARG`.

## Options

### Firewall rules

| Option | Effect |
|---|---|
| `-analyze-rules` | Prints the active configuration of each firewall profile, then analyzes each of the 10 policy stores: rule status errors, missing application files, missing app packages, unresolved SID owners, top rules by WFP filter count, and duplicates. |
| `-clean-rules` | Runs the same analysis and prompts to delete problem rules. Opens stores read/write, except RSOP and static Windows Service Hardening, which deny it: those are opened read-only, analyzed, and never modified. Skips Group Policy, MDM, and configurable Windows Service Hardening entirely, including their analysis. |
| `-analyze-inbound-rules` | Classifies inbound allow rules in each store by profile. |

`-clean-rules` deletes in this order within each store: rules with missing applications, rules with unresolved SIDs or no local profile, then duplicates.

Prompts accept `y` (delete this one), `n` (keep it), `s` (skip the rest of this category in this store), and `a` (delete the rest of this category in this store without asking). For duplicates, `y` deletes all but one. If the duplicates have different names, a second prompt asks which name to keep.

`-analyze-inbound-rules` details:

- Despite the help text saying "active", it includes disabled rules and counts them separately.
- Rules are grouped as Private only, Domain (without Public), or Public (with any other profile).
- A Private or Domain rule equivalent to a Public rule moves to a fourth group, because it is effectively open on Public too. Equivalence ignores profile and enabled state. For Private rules it also ignores the Local Subnet keyword.
- This is an analysis classification; the rules are not changed.

### Shields Up

| Option | Effect |
|---|---|
| `-enable-shields-up` | Blocks all inbound traffic on all three profiles. |
| `-enable-shields-up:<profile>` | Same, for one profile: `public`, `private`, or `domain`. |
| `-disable-shields-up` | Clears the setting on all three profiles. |
| `-disable-shields-up:<profile>` | Same, for one profile. |

After changing the setting, the tool prints each profile's configuration.

- Only one form of each option is allowed per run. You cannot pass two profiles, as in `-enable-shields-up:public -enable-shields-up:private`; run the tool twice.
- **Do not combine enable and disable.** The parser accepts it, the target profiles are merged, and disable wins. `-enable-shields-up:public -disable-shields-up:private` disables Shields Up on both profiles.
- A failed change is printed for that profile, but the process still exits `0`.

### App packages

| Option | Effect |
|---|---|
| `-list-app-packages` | Prints every package with version, architecture, publisher, full and family names, and their derived AppContainer SIDs. |
| `-analyze-app-package-rules` | Classifies, per store, how rules reference packages: package family name, package SID, or only a name beginning with `@`. Split by rule schema version (after 2.31, or 2.31 and earlier). `-verbose` adds rule IDs. |

### WFP

| Option | Effect |
|---|---|
| `-analyze-wfp` | Prints callouts, sublayers, providers, filter totals, and each third-party callout with its filters. `-verbose` adds per-layer callouts and per-sublayer, per-provider, and per-callout counts. |
| `-wfp-events` | Subscribes to WFP net events and prints them until Ctrl-C. Classify drops also show the filter, callout, layer, and sublayer. |
| `-tcpip-events` | Prints TCP/IP packet-drop ETW events until Ctrl-C. |

`-tcpip-events` deliberately omits noise, so its output is not every drop. It ignores:

- Transport drops to broadcast or multicast addresses, to port 0, or to addresses not on this machine.
- Network drops where the protocol is HOPOPT, TCP, or UDP.
- Framing drops with reason code 3 (invalid Ethernet type).

"Third-party" is the tool's classification: any callout not in its built-in list. It is not a verified publisher.

### Temporary callout removal

| Option | Effect |
|---|---|
| `-remove-callouts` | Lists third-party callout drivers, prompts `y`/`n` per driver, and deletes the filters that invoke the approved drivers' callouts. Waits, then restores them. |
| `-driver <name>` | Requires `-remove-callouts`. Selects drivers by case-insensitive **substring** and **skips the confirmation prompt**, so a short name can match several drivers. |
| `-signal-restore-callouts` | Tells a waiting `-remove-callouts` instance to restore its filters. Must be the only option besides `-verbose`. |

The usage text says `-driver` must follow `-remove-callouts`, but the parser accepts either order.

Filters are restored when any of these happens:

- Enter is pressed in the waiting console.
- Another instance runs `-signal-restore-callouts`.
- A console control event such as Ctrl-C or closing the console arrives, at any point once the driver list has been shown.

The signal is the named event `FwDiagnoseCalloutsLoadedEvent`, in the session's local namespace, so run the signaling instance in the same logon session and at the same elevation.

If restoration fails, the tool prints a recommendation to reboot. See [Known issues](ARCHITECTURE.md#known-issues) for cases where restoration does not run.

### Output modifiers

| Option | Effect |
|---|---|
| `-verbose` | Adds detail to analysis output. |
| `-json <path>` | Also writes a UTF-8 JSON report, overwriting `path`. |
| `-?` | Prints usage and exits `0`, wherever it appears. Cannot be combined with `-json`. |

`-json` rules:

- It may appear only with `-analyze-rules`, `-clean-rules`, Shields Up commands, and `-verbose`, and needs at least one of the first three. Anything else fails before any work is done.
- The path is the next argument and cannot begin with `-`. `-json` may appear only once.
- It exports only firewall-profile configuration and per-store rule status. Every report has `run.status` of `partial` on success or `failed` on a nonzero exit, and a `json_export_incomplete` warning. `completed` is not yet produced at run level.
- The file is created and truncated at startup, held open exclusively, and written only at the end. If the process dies, the file is empty.
- `-jsonl` appears in the plan but is not implemented.

Field-level details are in [JSON-OUTPUT-PLAN.md](JSON-OUTPUT-PLAN.md).

## Combining options

Most commands can be combined and run in this fixed order, regardless of the order typed:

1. `-analyze-rules` / `-clean-rules` (if both are given, it cleans)
2. `-analyze-inbound-rules`
3. Shields Up change
4. `-analyze-wfp`
5. `-wfp-events` (blocks until Ctrl-C)
6. `-tcpip-events` (blocks until Ctrl-C)

These exceptions take over the run. Options are checked in this order:

| Condition | Result |
|---|---|
| `-?` present | Prints usage and exits `0`. |
| `-signal-restore-callouts` present | Signals and exits. Any other option except `-verbose` is an error. |
| `-list-app-packages` present | Lists packages and exits. Other commands **and unrecognized arguments are ignored**. |
| `-analyze-app-package-rules` present | Analyzes and exits, same as above. |
| Any argument left unrecognized | Error, `ERROR_BAD_ARGUMENTS`. |
| `-remove-callouts` present | Runs only callout removal. Other commands are ignored. |

Passing only `-verbose` loads all data, prints nothing, and exits `0`.

## Privileges

Run elevated. The code enforces this unevenly:

| Command | Behavior when not elevated |
|---|---|
| `-analyze-wfp`, `-wfp-events` | Explicit check; fails with `ERROR_ACCESS_DENIED` and a message. |
| `-clean-rules` | Store open is denied; a message is printed. |
| `-analyze-rules`, `-analyze-inbound-rules`, `-analyze-app-package-rules` | A store that is denied is reported as not analyzed, and the remaining stores are still loaded. |
| Shields Up | Printed per profile; exit `0`. |
| `-remove-callouts`, `-tcpip-events` | No explicit check; the underlying API calls fail. |
| `-list-app-packages` | Uses `PackageManager.FindPackages()` for all users. A failure is printed to stderr and the list is empty. |

Every run other than the early-exit commands also starts an ETW session to get callout driver names, which takes at least one second. Without the rights for that, an error is printed, and third-party driver names will be missing.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran to the end. **Does not mean every operation succeeded**; many failures are printed and not propagated. |
| `E_INVALIDARG` (`0x80070057`) | No arguments, conflicting shields options, a missing `-driver` value, or an invalid `-json` usage. |
| `ERROR_BAD_ARGUMENTS` (160) | Unrecognized argument. |
| `ERROR_INTERNAL_ERROR` (1359) | The restore event could not be opened, or an unexpected `std::exception`. |
| Other | The `HRESULT` from an uncaught WIL error. |

`-remove-callouts` exits through `TerminateProcess(..., 0)` after restoring, so it reports `0` even if restoration failed.

## Examples

```powershell
# Health check with full detail
FwDiagnose.exe -analyze-rules -verbose

# Rule analysis with a JSON report
FwDiagnose.exe -analyze-rules -json .\report.json

# Inbound exposure (run separately: -json rejects this command)
FwDiagnose.exe -analyze-inbound-rules

# Lock down the Public profile
FwDiagnose.exe -enable-shields-up:public

# Watch drops while reproducing a problem
FwDiagnose.exe -wfp-events

# Test without one callout driver, then restore from a second console
FwDiagnose.exe -remove-callouts -driver exampledrv
FwDiagnose.exe -signal-restore-callouts
```
