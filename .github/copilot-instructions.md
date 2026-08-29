# Repository overview

This repository is a Windows-only native C++ solution containing independent console tools. The projects do not link to a shared repository library; each executable owns its command-line flow and Windows API integration.

- `FwDiagnose` is the largest tool. `FwDiagnose.cpp` parses options and coordinates firewall-rule analysis, app-container/IP inspection, and Windows Filtering Platform (WFP) enumeration implemented across the `FirewallRules`, `Wfp*`, `AppContainers`, and `IpProperties` modules.
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

There is no checked-in automated test project or test runner. Use the smallest affected executable as the single-test equivalent; non-mutating command-line smoke checks include:

```powershell
.\x64\Debug\FwDiagnose.exe -?
.\x64\Debug\MultipathLatencyAnalyzer.exe -?
.\x64\Debug\PrintConnectionProfiles.exe
```

`SetNetworkCategory` changes system network configuration, `MigrateIpProperties` writes interface configuration, and several `FwDiagnose` modes require elevation or modify firewall/WFP state. Do not use those as routine smoke tests without an appropriate test machine.

Only `MultipathLatencyAnalyzer` has a checked-in formatting configuration. Check one file with:

```powershell
clang-format --dry-run --Werror .\MultipathLatencyAnalyzer\main.cpp
```

Apply it to changed files in that project with `clang-format -i <files>`. There is no repository-wide lint command.

## Codebase conventions

- Use WIL for Windows error propagation and resource ownership: `THROW_IF_FAILED`, `THROW_LAST_ERROR_IF`, `FAIL_FAST_*`, `wil::com_ptr`, and `wil::unique_*` are preferred over manual cleanup. Initialize COM/WinRT explicitly at executable entry points.
- Preserve the established failure model. Top-level entry points commonly use function-try-blocks; asynchronous/thread-pool callbacks are `noexcept` and fail fast on unexpected exceptions because exceptions must not escape Windows callbacks.
- Use wide strings and `wmain` for command lines that interact with Unicode Windows APIs. Keep API-specific types (`GUID`, `HANDLE`, `HRESULT`, interface indices) visible rather than converting them to generic abstractions.
- Projects compile as the latest C++ language mode with level-4 warnings, warnings as errors, SDL checks, and the static MSVC runtime. New code must remain warning-clean for all supported architectures.
- Formatting is not uniform across the entire repository. `MultipathLatencyAnalyzer` follows its local `.clang-format` (4 spaces, 120 columns, Allman-style braces, no include sorting); older `FwDiagnose`, `MigrateIpProperties`, and `ctl` code often uses tabs. Match the surrounding file and avoid repository-wide reformatting.
- Keep platform-dependent behavior behind existing RAII wrappers. In DualSTA code, the WLAN handle must remain open for the lifetime of the secondary connection, network-status subscriptions must be revoked during shutdown, and sockets bound to a secondary interface must be rebuilt when connectivity changes.
- Follow the `ctThreadIocp` overlapped-I/O contract: obtain a fresh `OVERLAPPED` with `new_request` for every operation, call `cancel_request` only when the API fails before queuing completion, and keep buffers/state alive until the callback runs.
- Keep `MigrateIpProperties` behavior aligned across IPv4/IPv6 and `ActiveStore`/`PersistentStore`; interface properties, static addresses, and routes are migrated as separate phases.
