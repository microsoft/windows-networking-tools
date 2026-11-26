# FwDiagnose

FwDiagnose is a native Windows console tool for diagnosing Windows Firewall rules and the Windows Filtering Platform (WFP) state beneath them. It answers questions that are hard to answer from `netsh` or the Firewall UI:

- Which rules are broken, duplicated, or left over from uninstalled apps and deleted users?
- Which rules actually allow inbound traffic, and on which profiles?
- Which firewall rules generate the most WFP filters?
- Which third-party callout drivers are in the network path?
- Is a third-party callout causing this problem? (Remove its filters temporarily, test, restore.)
- Why was this packet dropped, live?

## What it does

| Area | Commands | Changes the system? |
|---|---|---|
| Rule health across 10 policy stores | `-analyze-rules` | No |
| Rule cleanup, with prompts | `-clean-rules` | **Yes** - deletes rules |
| Inbound exposure by profile | `-analyze-inbound-rules` | No |
| Shields Up (block all inbound) | `-enable-shields-up`, `-disable-shields-up` | **Yes** |
| App-package inventory and rule references | `-list-app-packages`, `-analyze-app-package-rules` | No |
| WFP inventory | `-analyze-wfp` | No |
| Live drop events | `-wfp-events`, `-tcpip-events` | No |
| Temporary callout filter removal | `-remove-callouts`, `-signal-restore-callouts` | **Yes** - deletes, then restores, WFP filters |
| Structured output (partial) | `-json <path>` | Writes a file |

See [COMMAND-LINE.md](COMMAND-LINE.md) for every option, how options combine, privileges, and exit codes.

## Quick start

From an elevated Visual Studio Developer PowerShell at the repository root:

```powershell
nuget restore WindowsNetworkingTools.sln -NonInteractive
msbuild FwDiagnose\FwDiagnose.vcxproj /m /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir=$PWD\

.\x64\Debug\FwDiagnose.exe -analyze-rules
.\x64\Debug\FwDiagnose.exe -analyze-inbound-rules -verbose
.\x64\Debug\FwDiagnose.exe -analyze-wfp
```

Run `nuget restore` first: `FwDiagnose.vcxproj` needs C++/WinRT 3.0.260818.1 and WIL 1.0.260126.7, and a `packages\` folder from an earlier restore may only hold older versions.

Use the published binaries in `LatestBuilds\` to run the tool, and a fresh build to validate source changes.

> **Before using a mutating command:** read [Known issues](ARCHITECTURE.md#known-issues). A crash or forced kill during `-remove-callouts` strands the removed filters until reboot. Use a test machine.

## Documentation

| File | Contents |
|---|---|
| [COMMAND-LINE.md](COMMAND-LINE.md) | Options, combinations, privileges, exit codes |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Modules, execution flow, data model, design rules, known issues |
| [JSON-OUTPUT-PLAN.md](JSON-OUTPUT-PLAN.md) | Design and per-command schema plan for `-json` / `-jsonl`; only partly implemented |

Coding conventions and build details for the whole repository are in [`.github/copilot-instructions.md`](../.github/copilot-instructions.md).

These documents describe the source at commit `6ca81b1`. They were written by reading the code; the tool was not run to produce them.
