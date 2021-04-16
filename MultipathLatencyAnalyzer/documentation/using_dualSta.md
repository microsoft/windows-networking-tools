# Using DualSTA in your application

Windows [Wlan API](https://docs.microsoft.com/en-us/windows/win32/api/wlanapi/)
provides the functions to enable the DualSTA feature and to query a secodnary
interface. It is also recommended to use the [Networking connectivity
API](https://docs.microsoft.com/en-us/uwp/api/Windows.Networking.Connectivity.NetworkInformation?view=winrt-19041)
to determine when a secondary interface is available and ready.

## Enabling DualSTA

First thing, the application needs to indicate to the OS it wants to use a
secondary interface. This will let the OS connect the secondary interface if
needed.

1. Open a handle to the WLAN service (`WLANOpenHandle`)

    This handle **must** remain opened for the entire time the application with
    be using the DualSTA feature. The OS will disconnect the secondary
    interface if it detects no client applications are using it.

    👁️‍🗨️ See `OpenWlanHandle` in ["adapters.cpp"](../adapters.cpp)

2. Get a WLAN interface GUID (`WlanEnumInterfaces`)

    If there are several WLAN interfaces in the system, you can pick any of
    them. DualSTA is enabled globally, for all interfaces. We simply need a
    GUID to call the `WlanSetInterface` API.

    👁️‍🗨️ See `GetPrimaryWlanInterfaceGuids` in ["adapters.cpp"](../adapters.cpp)

3. Enable secondary STA connections (`WlanSetInterface`)

    Using the opcode `wlan_intf_opcode_secondary_sta_synchronized_connections`
    and the GUID from step 2, a call to `WlanSetInterface` will enable
    secondary STA connections.

    👁️‍🗨️ See `RequestSecondaryInterface` in ["adapters.cpp"](../adapters.cpp)

This is it! At this point, the WLAN service will bring up a secondary interface
for each Wi-Fi adapter supporting DualSTA (this depends on the driver). If
there is a Wi-Fi connection to a network with several bands, it will start
connecting the secondary interface to the network.

## Querying a secondary interface (and when not to do it)

To send data over the secondary interface, we will need to bind a socket to it.
Without it, the traffic on this socket would go through the same interface as
for any other socket of your application.  However, this also mean the OS
cannot route the packets through the right interface in some situations. For
instance:

- the target address is behind a VPN
- the traffic needs to go through a virtual switch
- there is a connected ethernet adapter

Therefore it is recommended to only use a secondary interface when the
situation is "simple". In more complex cases, it is recommended to keep using a
single interface.

In this context, "simple" means that the primary IP interface is directly
matching a physical WLAN adapter. This ensures the secondary interface traffic
will be routed correctly.  When the IP interface directly matches a physical
WLAN adapter, they share the same GUID.

1. Get the GUID of the primary IP interface (`GetInternetConnectionProfile()`)

    In most scenario, you can get the interface GUID from the preferred
    internet connection profile:

    ```
    NetworkInformation::GetInternetConnectionProfile().NetworkAdapter().NetworkAdapterId();
    ```
    👁️‍🗨️ See `GetPrimaryInterfaceGuid` in ["adapters.cpp"](../adapters.cpp)

    *Remark*: If your application needs to communicate on local networks, you
    may need more complex solutions such as `GetBestInterfaceEx`.

2. Find a matching WLAN adapter (`WlanEnumInterfaces`)

    Once again, `WlanEnumInterfaces` provide the list of the Wi-Fi interfaces
    in the system. It is then simply a matter of looking if one is matching the
    GUID from step 1.

    👁️‍🗨️ See `GetSecondaryInterfaceGuid` in ["adapters.cpp"](../adapters.cpp)

3. Query for the secondary interface (`WlanQueryInterface`)

    Using the opcode `wlan_intf_opcode_secondary_sta_interfaces` and the
    primary interface GUID, a call to `WlanQueryInterface` will return the list
    of secondary interfaces related to the primary.

    👁️‍🗨️ See `GetSecondaryInterfaceGuid` in ["adapters.cpp"](../adapters.cpp)

## Using a secondary interface

We now have identified a secondary interface. Let's see how to use it!

The secondary interface GUID may not be usable right away: there might be a
delay until the corresponding IP interface is ready and can access the network.
This happens for instance when the secondary WLAN adapter is still connecting
to the network.

1. Wait for connectivity (`GetNetworkConnectivityLevel`)

    The Network Connectivity API indicates when an interface is ready through
    the connection profiles. It is recommended to wait until the secondary
    interface is present with a connectivity level different from
    `NetworkConnectivityLevel::None`.

    👁️‍🗨️ See `IsAdapterConnected` in ["adapters.cpp"](../adapters.cpp)

2. Bind a socket to the secondary interface (`setsockopt`)

    It is necessary to bind a socket to the secondary interface to use it, by
    calling `setsockopt` with the options `IP_UNICAST_IP` or `IPV6_UNICAST_IF`.
    This option requires an interface index. It can be obtained from the
    secondary interface GUID by using `ConvertInterfaceGuidToLuid` and
    `ConvertLuidToIndex` (from the "netioapi.h" header).

    👁️‍🗨️ See `SetSocketOutgoingInterface` and in ["socket_utils.h"](../socket_utils.h)
    and `ConvertInterfaceGuidToIndex` in ["adapter.cpp"](../adapter.cpp)

From this point, the secondary interface is completely setup and the socket
can be used as a normal socket.

## Monitoring network status change notifications

While the application is running, the network conditions could change. For
instance, an ethernet connection could be setup, and the Wi-Fi connection be
disconnected. For non-bounded sockets, the OS automatically redirect the
traffic toward the correct IP interface. But the secondary socket has to be
bound to the secondary interface: it will have to be enabled and disabled
manually depending on the network status.

This can be done by subscribing to the network status change notifications from
`NetworkInformation::NetworkStatusChanged`. It allows to monitor when the
primary interaface changes. Then, the secondary interface can be tear down,
and/or a new secondary interface can be setup if the new primary interface
supports it.

👁️‍🗨️ See `SetupSecondaryInterface` in ["stream_client.cpp"](../stream_client.cpp)

Using `-loglevel:2` or higher and running the tool with both a Wi-Fi and an
ethernet connection can help observing this behavior. Pluging or unpluging the
ethernet cable will cause the primary interface to change, and the secondary
interface will follow.