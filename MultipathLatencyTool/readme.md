# DualSTA_SampleTool

DualSTA_SampleTool is a simple network performance measurement program with a
focus on Windows "DualSTA" Wi-Fi feature.

This feature allows Windows to use simultaneous connections to multiple bands
of a wireless network (5GHz and 2.4GHz for instance). Applications can
query for the secondary interfaces and to bind sockets to those interfaces.
After binding, applications can use the sockets to send data over the secondary
interface.

## Project overview

This project has two main goals:

### Demonstrating how to best use the DualSTA feature

DualSTA_SampleTool aims to demonstrate how to enable and make use of a
secondary Wi-Fi interface in a realistic use case, using modern C++.

More specificaly, it demonstrates how an applicication is expected to:
- enable the "DualSTA" feature
- request a secondary interface
- bind a socket on the secondary interface
- listen to network status change notification to dynamically enable or disable
  the secondary interface

DualSTA_SampleTool show how to use a secondary interface in a best-effort basis: it
prioritizes sending data over the primary interface as soon as possible and
over the best interface as possible. A secondary interface is used whenever
possible and is dynamically updated when the network status changes.

However, this project does **not** aim to provide any guidance about how
communication should be split between the two interfaces or reassembled after
reception, or how a higher level protocol should make use of the two interfaces.

### Providing statistics over network performances

DualSTA_SampleTool collects latency data on the packets it sends to an echo
server.  It displays latency statistics, with a focus on evaluating the impact
of a secondary interface on a Wi-Fi connection.

It collects the latency *as seen from the app* (as opposed to at the hardware
level): the overhead introduced by the OS is included.

DualSTA_SampleTool makes use of a Wi-Fi secondary interface on a best-effort
basis: it supports systems, configuration, and networks where a using secondary
interface is not possible (ethernet for instance) by using only one interface
in those situation. It handles switching seamlessly between using a secondary
interface or not.

## Quick Start

The application is a simple echo program that tracks the latency of packets
between a client and a server.

### Using DualSTA_SampleTool

The latest binaries are present in the "LatestBuilds" folder.

To start the server, run
```
DualSTA_SampleTool.exe -listen:*
```

To start the client, with SERVER_IP being the IP address of the server, run
```
DualSTA_SampleTool.exe -target:"SERVER_IP"
```

### Building DualSTA_SampleTool

To build the project, you need Visual Studio 2019 version 2.8 or higher and
Windows SDK version 10.0.21318.0 (or more recent, in which case you need to
update the version in the project file).

From there, simply build the project from Visual Studio.

## Using DualSTA in your application

The DualSTA feature must be enabled using Windows [Wlan
API](https://docs.microsoft.com/en-us/windows/win32/api/wlanapi/). It is also
recommended to use the [Networking connectivity
API](https://docs.microsoft.com/en-us/uwp/api/Windows.Networking.Connectivity.NetworkInformation?view=winrt-19041)
to determine when the secondary interface should be used.

### Enabling DualSTA

First thing, the application needs to indicate to the OS it wants to use a
secondary interface. This will let the OS connect the secondary interface if
needed.

1. Open a handle to the WLAN service (`WLANOpenHandle`)

    This handle **must** remain opened for the entire time the application with
    be using the DualSTA feature. The OS will disconnect the secondary
    interface if it detects no client applications are using it.

    👁️‍🗨️ See `OpenWlanHandle` in ["adapters.cpp"](adapters.cpp)

2. Get a WLAN interface GUID (`WlanEnumInterfaces`)

    If there are several WLAN interfaces in the system, you can pick any of
    them. DualSTA is enabled globally, for all interfaces. We simply need a
    GUID to call the `WlanSetInterface` API.

    👁️‍🗨️ See `GetPrimaryWlanInterfaceGuids` in ["adapters.cpp"](adapters.cpp)

3. Enable secondary STA connections (`WlanSetInterface`)

    Using the opcode `wlan_intf_opcode_secondary_sta_synchronized_connections`
    and the GUID from step 2, a call to `WlanSetInterface` will enable
    secondary STA connections.

    👁️‍🗨️ See `RequestSecondaryInterface` in ["adapters.cpp"](adapters.cpp)

This is it! At this point, the WLAN service will bring up a secondary interface
for each Wi-Fi adapter supporting DualSTA (this depends on the driver). If
there is a Wi-Fi connection to a network with several bands, it will start
connecting the secondary interface to the network.

### Querying a secondary interface (and when not to do it)

To send data over the secondary interface, we will need to bind a socket to it.
Without it, the traffic on this socket would go through the same interface as
for any other socket of your application.  However, this also mean the OS
cannot route the packets through the right interface in some situations. For
instance:

- the target address is behind a VPN
- the traffic needs to go through a virtual switch
- there simply is a connected ethernet adapter. It is generally better to
  simply use it

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
    👁️‍🗨️ See `GetPrimaryInterfaceGuid` in ["adapters.cpp"](adapters.cpp)

    *Remark*: If your application needs to communicate on local networks, you
    may need more complex solutions such as `GetBestInterfaceEx`.

2. Find a matching WLAN adapter (`WlanEnumInterfaces`)

    Once again, `WlanEnumInterfaces` provide the list of the Wi-Fi interfaces
    in the system. It is then simply a matter of looking if one is matching the
    GUID from step 1.

    👁️‍🗨️ See `GetSecondaryInterfaceGuid` in ["adapters.cpp"](adapters.cpp)

3. Query for the secondary interface (`WlanQueryInterface`)

    Using the opcode `wlan_intf_opcode_secondary_sta_interfaces` and the
    primary interface GUID, a call to `WlanQueryInterface` will return the list
    of secondary interfaces related to the primary.

    👁️‍🗨️ See `GetSecondaryInterfaceGuid` in ["adapters.cpp"](adapters.cpp)

### Using a secondary interface

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

    👁️‍🗨️ See `IsAdapterConnected` in ["adapters.cpp"](adapters.cpp)

2. Bind a socket to the secondary interface (`setsockopt`)

    It is necessary to bind a socket to the secondary interface to use it, by
    calling `setsockopt` with the options `IP_UNICAST_IP` or `IPV6_UNICAST_IF`.
    This option requires an interface index. It can be obtained from the
    secondary interface GUID by using `ConvertInterfaceGuidToLuid` and
    `ConvertLuidToIndex` (from the "netioapi.h" header).

    👁️‍🗨️ See `SetSocketOutgoingInterface` and in ["socket_utils.h"](socket_utils.h)
    and `ConvertInterfaceGuidToIndex` in ["adapter.cpp"](adapter.cpp)

From this point, the secondary interface is completely set up and the socket
can be used as a normal socket.

### Monitoring network status change notifications

While the application is running, the network conditions could change. For
instance, an ethernet connection could be setup, and the Wi-Fi connection be
disconnected. For non-bounded sockets, the OS automatically redirect the
traffic toward the correct IP interface. But the secondary socket has to be
bound to the secondary interface: it will have to be enabled and disabled
manually depending on the network status.

This can be done by subscribing to the network status change notifications from
`NetworkInformation::NetworkStatusChanged`. It allows to check whether the
primary changes and to tear down or setup a secondary interface when needed.

👁️‍🗨️ See `SetupSecondaryInterface` in ["stream_client.cpp"](stream_client.cpp)

## Using DualSTA_SampleTool

DualSTA_SampleTool is a simple echo program that track the latency of packets.
It then displays statistics over the the collected data, allowing to evaluate
the impact of a secondary interface.

The program is composed of a client and a server. The server is simply echoing
back any packet it receives after adding a timestamp.

The client allows to send data at different rates, over one interface or
duplicated over two interfaces.  It will then display a set of statistics (lost
frames, average and median latency, jitter...) for the primary interface, the
secondary interface and the *effective* connection. The effective statistics
use the latency between the time a packet is first sent and when its echo is
first received, ignoring on which interface each event occurs.

It is also possible to collect the raw timestamp in a file for more analysis.

### How to run it

The server and the client must each be run on a different device connected to the same
network. To test the DualSTA feature, the client must run on a device with a
compatible Wi-Fi NIC and driver. Otherwise, the secondary interface will not be enabled.
The server can be run on any device.

To run the server, simply run the application with the command-line parameter
`-listen:*`.  This will cause the application to begin listening on all
interfaces on the default application port (8888). An IP address may be given
instead of `*` to bind to that specific address. The server will simply echo
back whatever it receives on that port until it is stopped using Ctrl+C.

To run the client, run the application with the command-line parameters
`-target:SERVER_IP -duration:N`, where SERVER_IP is the IP address of the
listening server and N is the number of seconds to run the tool. The client
will then begin streaming data to the server.

### Parameters

`-?`

Access the help

`-port:<N>`

Changes the port used for communications.

`-loglevel:<N>`

Controls the logs verbosity. Goes from 0 to 5. The level 2 provides additionnal details about the behavior of the secondary interface.
The level 5 is extremely verbose and should generaly avoided.

`-prepostrecvs:<N>`

Controls the number of receive operations the application will keep posted on
the Windows IO Completion Port for the socket. See the Windows Threadpool API
documentation that was introduced in Vista for more information, as well as the
WinSock documentation for WSARecv and WSASend.

#### Parameters for the client only:

`-bitrate:<sd,hd,4k,N>`

The rate at which the application send data. The values correspond to streaming
rates for common video streams (sd is 3 megabits per seconds, hd is 5 and 4k is
25). It is also possible to specify a custom value in megabit per second.

`-framerate:<N>`

How many datagrams are sent during each send operation (effectively grouping
them in a burst). A value too high or too low might cause packet loss rate or
impact the bitrate.

`-secondary:<0,1>`

Whether to use the secondary interface. When set to `0`, a secondary interface
won't be queried, which can be useful for comparison purpose. Note that setting
this parameter to `1` will only cause the application to use a secondary
interface on a best effort basis.

`-output:<path>`

Path to a file where the raw timestamps will be stored in csv format. Each line
will contain the sequence number of a datagram and the timestamp (in
microseconds) at which it was sent by the client, echoed by the server, and
received by the client, both for the primary and secondary interface. -1
indicate the event didn't occurred.

Note the timestamps are collected using QPC, which mean they are relative: each
timestamp should only be compared with timestamp from the same device, there is
no relation between the echo timestamps collected on the server and the send
and received timestamps collected on the client.

### Output

The output is the classic statistic functions (average, median, standard
deviation...) on the collected latencies. The result are displayed for the
primary interface, the secondary interface and the *effective interface*.

The latency of a packet on the *effective interface* is the difference between
the time it was first sent by the application and the time its echo was first
received, *independently* of the interface these two events happened on: it
represents the latency between the time the application tried to send data and
the time it got the answer.

Lost packets are ignored in all statistics: there is no penalty or retry.

For more detailed analysis of the results, the raw timestamps can be retrieved
using the option `-output`.

## Latency analysis example

The result below were obtained by running DualSTA_SampleApp for one hour on a client connected over Wi-Fi and a server connected to the access point directly over ethernet:

```
> .\DualSTA_SampleTool.exe -target:"10.0.0.192" -prepostrecvs:5 -bitrate:hd -framerate:30 -duration:3600 -output:latencyData.csv

-----------------------------------------------------------------------
                            STATISTICS
-----------------------------------------------------------------------

--- OVERVIEW ---

18431992 kb (2303999 datagrams) were sent in 3599 seconds. The effective bitrate was 5121 kB/s.

The secondary interface prevented 2940 lost frames
The secondary interface saved 1399099 ms (9%)
266538 frames were received first on the secondary interface (11%)

--- DETAILS ---

Sent frames on primary interface: 2303999
Sent frames on secondary interface: 2296109

Received frames on primary interface: 2300051 (99%)
Received frames on secondary interface: 2294709 (99%)

Lost frames on primary interface: 3948 (0%)
Lost frames on secondary interface: 1400 (0%)
Lost frames on both interface simultaneously: 1008 (0%)

Average latency on primary interface: 6 ms
Average latency on secondary interface: 9 ms
Average effective latency on combined interface: 5 ms (9% improvement over primary)

Jitter (standard deviation) on primary interface: 9 ms
Jitter (standard deviation) on secondary interface: 6 ms
Jitter (standard deviation) on combined interfaces: 5 ms

Median latency on primary interface: 5 ms
Median latency on secondary interface: 8 ms
Median effective latency on combined interfaces: 5 ms (2% improvement over primary)

Interquartile range on primary interface: 1 ms
Interquartile range on secondary interface: 3 ms
Interquartile range latency on combined interfaces: 1 ms

Minimum / Maximum latency on primary interface: 1 ms / 674 ms
Minimum / Maximum latency on secondary interface: 1 ms / 289 ms

Corrupt frames on primary interface: 0
Corrupt frames on secondary interface: 0
```

In this case, the effective interface show a significant reduction of the latency and jitter.

A more detailed analysis of these results is present in [this Jupyter notebook](.\latency_analysis.ipynb).