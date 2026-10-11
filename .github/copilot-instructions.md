# Repository overview

This repository is a Windows-only native C++ solution containing independent console tools. The projects do not link to a shared repository library; each executable owns its command-line flow and Windows API integration.

- `FwDiagnose` is the largest tool. `FwDiagnose.cpp` parses options and coordinates firewall-rule analysis, app-container/IP inspection, and Windows Filtering Platform (WFP) enumeration implemented across the `FirewallRules`, `Wfp*`, `AppContainers`, and `IpProperties` modules.
- Firewall-rule analysis builds `NormalizedFirewallRule` records and uses `RuleDetailsComparison` for sorting and matching. Comparison policies can ignore profiles, the active flag, or local-subnet keywords; preserve these distinctions when changing duplicate detection or inbound-profile grouping. `NormalizedString` provides case-insensitive comparisons with an ASCII fast path and `CompareStringOrdinal` for non-ASCII text.
- `MigrateIpProperties` reads IP interface, address, and route state from one interface and writes it to another. Most implementation is header-based and uses WMI/CIM helpers from `ctl/`.
- `MultipathLatencyAnalyzer` is an asynchronous UDP echo client/server. The client sends measured datagrams over a primary socket and, when available, a DualSTA secondary Wi-Fi interface; `adapters.*` manages interface discovery, `measuredSocket.*` owns overlapped socket I/O, and `latencyStatistics.*` produces the results.
- `PrintConnectionProfiles` and `SetNetworkCategory` are focused examples over WinRT network-profile APIs and the COM Network List Manager API.
- `ctl/` contains reusable header-only wrappers for WMI, ETW, performance counters, and Windows thread-pool operations. It is currently consumed directly by projects through include paths rather than built as a separate target.

## Build and validation

Run commands from the repository root in a Visual Studio Developer PowerShell. The projects currently target the Visual C++ `v145` toolset, the installed Windows 10/11 SDK (`10.0`), and restore C++/WinRT plus WIL through `packages.config`.

```powershell
nuget restore WindowsNetworkingTools.sln -NonInteractive
msbuild WindowsNetworkingTools.sln /m /p:Configuration=Debug /p:Platform=x64
```

Build one project while iterating:

```powershell
msbuild WindowsNetworkingTools.sln /m /t:MultipathLatencyAnalyzer /p:Configuration=Debug /p:Platform=x64
```

The solution configurations are `Debug`/`Release` for `x86`, `x64`, and `ARM64`. When building a `.vcxproj` directly, use `Win32` instead of the solution-level `x86` platform name.

`LatestBuilds` contains published executables and symbols linked from `README.md`. Use freshly built output (such as `.\x64\Debug`) to validate source changes rather than those published binaries.

There is no checked-in automated test project or test runner. Use the smallest affected executable as the single-test equivalent; non-mutating command-line smoke checks include:

```powershell
.\x64\Debug\FwDiagnose.exe -?
.\x64\Debug\MultipathLatencyAnalyzer.exe -?
.\x64\Debug\PrintConnectionProfiles.exe
```

`SetNetworkCategory` changes system network configuration, `MigrateIpProperties` writes interface configuration, and several `FwDiagnose` modes require elevation or modify firewall/WFP state. Do not use those as routine smoke tests without an appropriate test machine.

The root `.clang-format` covers repository C++ files. `FwDiagnose` and `MigrateIpProperties` inherit it with tab indentation; `MultipathLatencyAnalyzer` keeps its own configuration. Check one file with:

```powershell
clang-format --dry-run --Werror .\MultipathLatencyAnalyzer\main.cpp
```

Apply it to changed C++ files with `clang-format -i <files>`. Exclude restored packages and generated/build output. Do not modify or include `MultipathLatencyAnalyzer` source or its `.clang-format` in repository-wide formatting or coding-guideline passes.

## Codebase conventions

- Test `std::optional` presence explicitly with `.has_value()`, including conditionals, ternary expressions, and error-check macros. Do not use the optional's implicit boolean conversion; checking a contained boolean value remains a separate operation.
- Use `enum class` rather than boolean parameters for behavior flags in new functions, so call sites state the flag's meaning explicitly.
- Keep function-call arguments on the function line when they fit; otherwise put each argument on its own line, including multiline lambdas (`BinPackArguments: false`, `AllowAllArgumentsOnNextLine: false`). Declaration parameters may all fit on one line (the declaration line or following line), or use one parameter per line (`BinPackParameters: false`, `AllowAllParametersOfDeclarationOnNextLine: true`). MultipathLatencyAnalyzer keeps its independent configuration.
- Preserve CRLF line endings in C++ source and header files. Do not introduce LF-only or mixed line endings; all clang-format configurations emit CRLF.
- Put each `template <...>` declaration on its own line, separate from the following declaration; clang-format enforces this with `BreakTemplateDeclarations: Yes`.
- Put the opening brace of a `case` or `default` block on its own line (`BraceWrapping.AfterCaseLabel: true`).
- Put every lambda-body opening brace on its own line (`BraceWrapping.BeforeLambdaBody: true`, `AllowShortLambdasOnASingleLine: None`).
- Always brace control-statement bodies, including single-statement `if`, `else`, `for`, `while`, and `do` bodies (`InsertBraces: true`). Inspect macro bodies separately because clang-format does not insert braces inside macro definitions.
- In `FwDiagnose`, `MigrateIpProperties`, `PrintConnectionProfiles`, and `ctl`, put function return types and their leading keywords/attributes on the line before the function name (`BreakAfterReturnType: All`, `BreakAfterAttributes: Never`). Trailing qualifiers such as `noexcept` remain with the declaration; these options are not repository-wide.

- Use WIL for Windows error propagation and resource ownership: `THROW_IF_FAILED`, `THROW_LAST_ERROR_IF`, `FAIL_FAST_*`, `wil::com_ptr`, and `wil::unique_*` are preferred over manual cleanup. Initialize COM/WinRT explicitly at executable entry points.
- Preserve the established failure model. Top-level entry points commonly use function-try-blocks; asynchronous/thread-pool callbacks are `noexcept` and fail fast on unexpected exceptions because exceptions must not escape Windows callbacks.
- Use wide strings and `wmain` for command lines that interact with Unicode Windows APIs. Keep API-specific types (`GUID`, `HANDLE`, `HRESULT`, interface indices) visible rather than converting them to generic abstractions.
- Projects compile as the latest C++ language mode with level-4 warnings, warnings as errors, SDL checks, and the static MSVC runtime. New code must remain warning-clean for all supported architectures.
- Follow the applicable `.clang-format` (4-column indentation, 120 columns, Allman-style braces, no include sorting). `FwDiagnose` and `MigrateIpProperties` use tabs; other projects use spaces. Prefer formatting changed files rather than unrelated repository-wide reformatting.
- Keep platform-dependent behavior behind existing RAII wrappers. In DualSTA code, the WLAN handle must remain open for the lifetime of the secondary connection, network-status subscriptions must be revoked during shutdown, and sockets bound to a secondary interface must be rebuilt when connectivity changes.
- Follow the `ctThreadIocp` overlapped-I/O contract: obtain a fresh `OVERLAPPED` with `new_request` for every operation, call `cancel_request` only when the API fails before queuing completion, and keep buffers/state alive until the callback runs.
- The UDP protocol in `MultipathLatencyAnalyzer\datagram.h` has a 24-byte header containing three 8-byte `long long` fields: sequence number, send timestamp, and echo timestamp. Timestamps are QPC-derived microseconds; the server updates the echo timestamp before returning the datagram. Keep client/server layout and timing units aligned.
- Primary and secondary sends share a sequence number and a single `LatencyMeasure` record indexed by that number. Missing timestamps are `-1`, not zero; effective multipath statistics select the earliest available send and receive timestamps across both interfaces. Preserve these semantics when changing collection, aggregation, or output.
- Keep `MigrateIpProperties` behavior aligned across IPv4/IPv6 and `ActiveStore`/`PersistentStore`; interface properties, static addresses, and routes are migrated as separate phases in that order. Preserve the existing `PersistentStore`-before-`ActiveStore` iteration within the migration helpers.

## Contributing

Follow the contribution requirements in `README.md`: most contributions require Microsoft's Contributor License Agreement, handled by the PR CLA bot, and the repository adopts the Microsoft Open Source Code of Conduct in `CODE_OF_CONDUCT.md`.
