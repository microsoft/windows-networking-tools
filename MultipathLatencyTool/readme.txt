========================================================================
    C++/WinRT DualSTA_SampleTool Project Overview
========================================================================

This project demonstrates how to make use of the new Windows Wi-Fi feature
with the project name "DualSTA". This feature allows Windows to maintain
simultaneous connections on multiple wireless bands. Applications are able
to query for the secondary interfaces and bind sockets to those interfaces.
After binding, data will be sent over the secondary interface when that socket
is used.

The steps to query for and enable secondary interfaces are as follows:

 1. Open a handle to the WLAN service (WlanOpenHandle)

    This handle MUST remain opened for the entire time the application will
    be using the DualSTA feature, as the system will disconnect the secondary
    interface if it detects no client applications are using the feature.

 2. Enumerate primary WLAN interfaces (WlanEnumInterfaces)

    Gather a list of the primary WLAN interface GUIDs. This will provide the
    application a complete list of Wi-Fi interfaces in the system. Note that
    not all of the returned interfaces may support DualSTA; support depends
    on the driver used by the adapter.

 3. Enable secondary STA connections (WlanSetInterface)

    Using the opcode `wlan_intf_opcode_secondary_sta_synchronized_connections`
    and the primary interface GUID, a call to WlanSetInterface will enable
    secondary STA connections on the primary interface GUID. This will bring
    up the secondary STA interface for the adapter.

 4. Query for the secondary STA interfaces (WlanQueryInterface)

    Using the opcode `wlan_intf_opcode_secondary_sta_interfaces` and the
    primary interface GUID, a call to WlanQueryInterface will return a list
    of secondary interfaces related to the given primary interface.

This procedure is in the "adapters.cpp" file in the functions "GetPrimaryInterfaceGuid",
"SetSecondaryInterfaceEnabled" and "GetSecondaryInterfaceGuids". The WLAN handle
is opened in "main.cpp" and passed in to these functions.

Once the primary and secondary interface GUIDs are known, the application may
then create a pair of sockets and set the outgoing interface option on each
socket. This option requires converting the interface GUIDs to interface indexes.
This can be done in the following manner:

 1. Convert the interface GUID to an interface LUID (ConvertInterfaceGuidToLuid)

 2. Convert the interface LUID to an interface index (ConvertInterfaceLuidToIndex)

Both of these APIs are part of the "netioapi.h" header.

After obtaining the interface indexes for both the primary and secondary interface,
a call to "setsockopt()" with the option "IP_UNICAST_IF" or "IPV6_UNICAST_IF" for
IPv4 and IPv6 respectively. See "SetSocketOutgoingInterface" in "socket_utils.h"
for more information.

An optional, but highly recommended step (and one done by this sample application),
is to detect network connectivity on both interfaces before proceeding with socket
creation and binding. This is most easily done using the NLM (Network List Manager)
APIs. Coupled with the WinRT APIs, this becomes a simple C++ lambda callback to wait
for the network change notifications and scan the list of network profiles to look
for both interfaces being registered as having internet connectivity. This procedure
is located in "WaitForConnectedWlanInterfaces" in "adapters.cpp".

========================================================================
    Running the DualSTA_Sample Application
========================================================================

The sample application is a simple echo program that tracks the latency between when
the message is sent and when it receives the echo back from the server. It then calculates
the average latency on each interface and presents some simple statistics to the user.

To run the server, simply run the application with the command-line parameter "-listen:*".
This will cause the application to begin listening on all interfaces on the default
application port (8888). An IP address may be given instead of "*" to bind to that
specific address. The server will simply echo back whatever it receives on that port
to the address that sent it.

To run the client, run the application with the command-line parameters
"-target:<SERVER_IP> -duration:<N>", where SERVER_IP is the IP address of the listening
server and N is the number of seconds to run the tool. The client will then begin
streaming data to the server and record the latency for each packet echoed back.
It will also track any lost packets and packets that come back mangled.

Additional parameters for the client:

 1. "-bitrate:<sd,hd,4k>"

    This option determines at what rate the application sends data. Each value corresponds
    to streaming rates for common video streams: sd is 3 megabits per second, hd is 5
    and 4k is 25.

 2. "-framerate:<N>"

    This option determines how many frames are sent during each send operation. Currently,
    values over approximately 30 will cause packets to be dropped.

Additional parameters for both the client and server:

 1. "-port:<N>"

    This option changes the port used for communications.

 2. "-prepostrecvs:<N>"

    This is an advanced option that controls the number of receive operations the application
    will keep posted on the Windows IO Completion Port for the socket. See the Windows Threadpool
    API documentation that was introduced in Vista for more information, as well as the WinSock
    documentation for WSARecvFrom and WSASendTo.