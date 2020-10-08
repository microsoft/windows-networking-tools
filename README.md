# Windows Networking Tools
This includes a variety of tools for managing networks and configurations on Windows devices, as well as tools demonstrating how to use relevant Networking APIs.

Binaries for latest sources are now available: https://github.com/microsoft/windows-networking-tools/tree/master/LatestBuilds


* **SetNetworkCategory**
  * This tool programmatically changes the Network Category (Firewall Profile) of the currently connected networks to either Public or Private.
  * It also demonstrates how to use the INetworkListManager APIs using modern C++, greatly simplifying the COM coding requirements. (https://docs.microsoft.com/en-us/windows/win32/api/netlistmgr/nn-netlistmgr-inetworklistmanager)

* **PrintConnectionProfiles**
  * This tool programmatically enumerates all the profiles on the device and prints all properties of the profile.
  * It also demonstrates how to use the Windows.Networking.NetworkInformation WinRT APIs using modern C++, greatly simplifying WinRT coding requirements. (https://docs.microsoft.com/en-us/uwp/api/Windows.Networking.Connectivity.NetworkInformation)

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
