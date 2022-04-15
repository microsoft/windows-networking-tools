# MultipathLatencyAnalyzer

MultipathLatencyAnalyzer is a simple network performance measurement program with a
focus on Windows "DualSTA" Wi-Fi feature.

This feature allows Windows to use simultaneous connections to multiple bands
of a wireless network (5GHz and 2.4GHz for instance). Applications can
query for the secondary interfaces and to bind sockets to those interfaces.
After binding, applications can use the sockets to send data over the secondary
interface.

## Project overview

This project has two main goals:

### Demonstrating how to best use the DualSTA feature

MultipathLatencyAnalyzer aims to demonstrate how to enable and make use of a
secondary Wi-Fi interface in a realistic use case, using modern C++.

More specificaly, it demonstrates how an applicication is expected to:
- enable the "DualSTA" feature
- request a secondary interface
- bind a socket on the secondary interface
- listen to network status change notification to dynamically enable or disable
  the secondary interface

MultipathLatencyAnalyzer show how to use a secondary interface in a best-effort basis: it
prioritizes sending data over the primary interface. A secondary interface is used whenever
possible and is dynamically updated when the network status changes.

However, this project does **not** aim to provide any guidance about how
communication should be split between the two interfaces or reassembled after
reception, or how a higher level protocol should make use of the two interfaces.

### Providing statistics over network performance

MultipathLatencyAnalyzer collects latency data on the datagrams it sends to an
echo server.  It displays latency statistics, with a focus on evaluating the
impact of a secondary interface on a Wi-Fi connection.

It collects the latency *as seen from the app* (as opposed to at the hardware
level): the overhead introduced by the OS is included.

MultipathLatencyAnalyzer makes use of a Wi-Fi secondary interface on a best-effort
basis: it supports systems, configuration, and networks where a using secondary
interface is not possible (ethernet for instance) by using only one interface
in those situation. It handles switching seamlessly between using a secondary
interface or not.

## Quick Start

The application is a simple echo program that tracks the latency of datagrams
between a client and a server.

### Using MultipathLatencyAnalyzer

The latest binaries are present in the "LatestBuilds" folder.

To start the server, run
```
MultipathLatencyAnalyzer.exe -listen:*
```

To start the client, with SERVER_IP being the IP address of the server, run
```
MultipathLatencyAnalyzer.exe -target:"SERVER_IP"
```

### Building MultipathLatencyAnalyzer

To build the project, you need Visual Studio 2019 version 2.8 or higher and
Windows SDK version 10.0.21318.0 (or more recent, in which case you need to
update the version in the project file).

From there, simply build the project from Visual Studio.

## Using DualSTA in your application

The DualSTA feature must be enabled using Windows [Wlan
API](https://docs.microsoft.com/en-us/windows/win32/api/wlanapi/).

- To enable DualSTA, call `WlanSetInterface` with the opcode
  `wlan_intf_opcode_secondary_sta_synchronized_connections`. This enable the feature gloably (for all interfaces), until the handle the the WLAN API is closed.

- To retrieve the secondary interfaces associated to a primary interface, call
  `WlanQueryInterface` with the opcode
  `wlan_intf_opcode_secondary_sta_interfaces` and the primary interface GUID.

It is also recommended to use the [Networking connectivity
API](https://docs.microsoft.com/en-us/uwp/api/Windows.Networking.Connectivity.NetworkInformation?view=winrt-19041)
to determine when a secondary interface can be used and when it is ready.

👁️‍🗨️ **Detailed explanations about how to use DualSTA in an application are available [here](documentation/using_dualSta.md)**.

## Using MultipathLatencyAnalyzer

MultipathLatencyAnalyzer is a simple echo program that track the latency of packets.
It then displays statistics over the the collected data, allowing to evaluate
the impact of a secondary interface.

The program is composed of a client and a server. The server is simply echoing
back any packet it receives after adding a timestamp.

The client allows to send data at different rates, over one interface or
duplicated over two interfaces.  It will then display a set of statistics (lost
datagrams, average and median latency, jitter...) for the primary interface, the
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

Changes the port used for communications. (*Default:8888*)

`-loglevel:<N>`

Controls the logs verbosity. Goes from 0 to 5. The level 2 provides additionnal details about the behavior of the secondary interface.
The level 5 is extremely verbose and should generaly avoided. (*Default: 3*)

`-prepostrecvs:<N>`

Controls the number of receive operations the application will keep posted on
the Windows IO Completion Port for the socket. See the Windows Threadpool API
documentation that was introduced in Vista for more information, as well as the
WinSock documentation for WSARecv and WSASend. (*Default: 2*)

#### Parameters for the client only:

`-bitrate:<sd,hd,4k,N>`

The rate at which the application send data. The values correspond to streaming
rates for common video streams (sd is 3 megabits per seconds, hd is 5 and 4k is
25). It is also possible to specify a custom value in megabit per second. (*Default: hd*)

`-grouping:<N>`

How many datagrams are sent during each send operation (effectively grouping
them in a burst). A value too high or too low might cause packet loss rate or
impact the bitrate. (*Default: 30*)

`-secondary:<0,1>`

Whether to use the secondary interface. When set to `0`, a secondary interface
won't be queried, which can be useful for comparison purpose. Note that setting
this parameter to `1` will only cause the application to use a secondary
interface on a best effort basis. (*Default: 1*)

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
> .\MultipathLatencyAnalyzer.exe -target:"10.0.0.192" -prepostrecvs:5 -bitrate:hd -grouping:30 -duration:3600 -output:latencyData.csv

-----------------------------------------------------------------------
                            STATISTICS
-----------------------------------------------------------------------

--- OVERVIEW ---

2303999 kB (2303999 datagrams) were sent in 3599 seconds. The effective bitrate was 5121.42 kb/s.

The secondary interface prevented 2940 lost datagrams
The secondary interface reduced the overall time waiting for datagrams by 1423860.94 ms (9.79%)
266538 datagrams were received first on the secondary interface (11.57%)

--- DETAILS ---

Sent datagrams on primary interface: 2303999
Sent datagrams on secondary interface: 2296109

Received datagrams on primary interface: 2300051 (99.82%)
Received datagrams on secondary interface: 2294709 (99.93%)

Lost datagrams on primary interface: 3948 (0.17%)
Lost datagrams on secondary interface: 1400 (0.06%)
Lost datagrams on both interface simultaneously: 1008 (0.04%)

Average latency on primary interface: 6.32 ms
Average latency on secondary interface: 9.24 ms
Average effective latency on combined interface: 5.69 ms (9.96% improvement over primary)

Jitter (standard deviation) on primary interface: 9.63 ms
Jitter (standard deviation) on secondary interface: 6.92 ms
Jitter (standard deviation) on combined interfaces: 5.74 ms

Median latency on primary interface: 5.60 ms
Median latency on secondary interface: 8.11 ms
Median effective latency on combined interfaces: 5.44 ms (2.85% improvement over primary)

Interquartile range on primary interface: 1.68 ms
Interquartile range on secondary interface: 3.36 ms
Interquartile range latency on combined interfaces: 1.56 ms

Minimum / Maximum latency on primary interface: 1.53 ms / 674.05 ms
Minimum / Maximum latency on secondary interface: 1.90 ms / 289.65 ms

Corrupt datagrams on primary interface: 0
Corrupt datagrams on secondary interface: 0
```

In this case, the effective interface show a significant reduction of the latency and jitter.

👁️‍🗨️ **A more detailed analysis of these results is present in [this Jupyter notebook](documentation/latency_analysis.ipynb)**.