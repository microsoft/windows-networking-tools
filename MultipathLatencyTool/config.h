#pragma once

#include "sockaddr.h"

#include <vector>

namespace multipath {
struct Configuration
{
    static constexpr unsigned long DefaultFramerate = 30;

    static constexpr unsigned long SendBitrateSd = 3 * 1024 * 1024;  // 3 megabits per second
    static constexpr unsigned long SendBitrateHd = 5 * 1024 * 1024;  // 5 megabits per second
    static constexpr unsigned long SendBitrate4k = 25 * 1024 * 1024; // 25 megabits per second
    static constexpr unsigned long DefaultBitrate = SendBitrateHd;

    static constexpr unsigned short DefaultPort = 8888;

    static constexpr unsigned long DefaultPrePostRecvs = 2;

    static constexpr unsigned long DefaultDuration = 60; // 1 minute

    static constexpr DWORD DefaultSocketReceiveBufferSize = 1048576;

    // the address on which to listen (server only)
    Sockaddr listenAddress{};

    // the target address to connect to (client only)
    Sockaddr targetAddress{};

    // the list of interfaces to bind against (client only)
    std::vector<int> bindInterfaces{};

    // the port to use for connections
    unsigned short port = DefaultPort;

    // the rate at which to send data (client only)
    unsigned long bitrate = DefaultBitrate;

    // the number of frames to send per tick (client only)
    unsigned long framerate = DefaultFramerate;

    // the number of receives to keep posted on the socket
    unsigned long prePostRecvs = DefaultPrePostRecvs;

    // the duration to run the application, in seconds (client only)
    unsigned long duration = DefaultDuration;
};
} // namespace multipath