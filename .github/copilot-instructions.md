# Copilot Instructions — windows-networking-tools

## Architecture

This is a Visual Studio solution (`WindowsNetworkingTools.sln`) containing **independent C++ console tools** for Windows networking management and API demonstrations. Each tool is its own `.vcxproj` with no shared runtime library between them.

| Tool | Purpose | Key APIs |
|------|---------|----------|
| **SetNetworkCategory** | Changes firewall profile (Public/Private) of connected networks | COM `INetworkListManager`, WIL |
| **PrintConnectionProfiles** | Enumerates and prints all network profile properties | C++/WinRT `Windows.Networking.Connectivity`, WIL |
| **QueryFirewallProperties** | Prints firewall profile info via WMI | WMI COM (`IWbemContext`), local `ctl/` WMI helpers |
| **MultipathLatencyAnalyzer** | Measures Wi-Fi performance including DualSTA | C++/WinRT, WIL, Winsock, WLAN API; most modular project with internal modules (adapters, logs, stream_client/server, etc.) |
| **ValidateLineEndings** | Validates/fixes line endings in source files | `std::filesystem`, `std::print`/`std::format`, WIL |

### Common dependencies

- **WIL (Windows Implementation Library):** Used across all projects for COM initialization (`wil::CoInitializeEx`), RAII resource management, and error handling. Provided via NuGet (`Microsoft.Windows.ImplementationLibrary`).
- **C++/WinRT:** Used by `PrintConnectionProfiles`, `MultipathLatencyAnalyzer`, and `SetNetworkCategory`. Provided via NuGet (`Microsoft.Windows.CppWinRT`).
- **`ctl/` directory:** Local WMI helper headers (`ctWmiInitialize.hpp`, `ctWmiService.hpp`, etc.) used by `QueryFirewallProperties`.

## Build

All projects target **C++ latest (`/std:c++latest`)**, platform toolset **v145**, with **Warning Level 4**, **SDL checks**, **Conformance mode**, and **Treat warnings as errors** enabled.

```powershell
# Build entire solution (requires Visual Studio 2022+ with C++ workload)
msbuild WindowsNetworkingTools.sln /p:Configuration=Release /p:Platform=x64

# Build a single project
msbuild SetNetworkCategory\SetNetworkCategory.vcxproj /p:Configuration=Release /p:Platform=x64

# Restore NuGet packages first if needed
nuget restore WindowsNetworkingTools.sln
```

Supported platforms: **x86**, **x64**, **ARM64** (except ValidateLineEndings which is x86/x64 only).

## C++ Code Quality Rules

Detailed rules with examples are in [`.github/instructions/cpp-code-quality.instructions.md`](.github/instructions/cpp-code-quality.instructions.md). Key points:

- **`static`** on all file-scoped globals and helper functions not used outside their translation unit
- **`const`** on all input parameters and references that aren't modified
- **`std::println`/`std::format`** over `printf` for new or modified output (C++23 `<print>` is available)
- **`%ls`** not `%ws` when `printf` is still used (portable wide-string specifier)
- **Range-based for loops** over iterator loops when the iterator isn't needed
- **`snake_case`** for local variables
- **Descriptive loop variable names** (not single letters or abbreviations)
