#pragma once

#include "sockaddr.h"

#include <filesystem>

namespace multipath {
struct Configuration
{
    // these values make debugging much easier
    static constexpr unsigned long c_testBitrate = 1024 * 8;

    static constexpr unsigned long c_bitrateSd = 3 * 1024 * 1024;  // 3 megabits per second
    static constexpr unsigned long c_bitrateHd = 5 * 1024 * 1024;  // 5 megabits per second
    static constexpr unsigned long c_bitrate4K = 25 * 1024 * 1024; // 25 megabits per second
    static constexpr unsigned long c_defaultBitrate = c_bitrateHd;
    static constexpr unsigned long c_defaultGrouping = 30;

    static constexpr unsigned short c_defaultPort = 8888;

    static constexpr unsigned long c_defaultPrePostRecvs = 2;

    static constexpr unsigned long c_defaultDuration = 60; // 1 minute

    static constexpr DWORD c_defaultSocketReceiveBufferSize = 1048576;

    // the address on which to listen (server only)
    ctl::ctSockaddr m_listenAddress{};

    // the target address to connect to (client only)
    ctl::ctSockaddr m_targetAddress{};

    // the port to use for connections
    unsigned short m_port = c_defaultPort;

    // the rate at which to send data (client only)
    unsigned long m_bitrate = c_defaultBitrate;

    // the number of datagrams to send per tick (client only)
    unsigned long m_grouping = c_defaultGrouping;

    // the number of receives to keep posted on the socket
    unsigned long m_prePostRecvs = c_defaultPrePostRecvs;

    // the duration to run the application, in seconds (client only)
    unsigned long m_duration = c_defaultDuration;

    // the file to output the results to (as csv)
    std::filesystem::path m_outputFile{};

    // behavior for the secondary WLAN interface
    bool m_useSecondaryWlanInterface = true;
};
} // namespace multipath