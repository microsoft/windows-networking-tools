#pragma once

#include "sockaddr.h"

#include <filesystem>

namespace multipath {
struct Configuration
{
    // these values make debugging much easier
    static constexpr unsigned long c_testSendBitrate = 1024 * 8;
    static constexpr unsigned long c_testFramerate = 1;

    static constexpr unsigned long c_sendBitrateSd = 3 * 1024 * 1024; // 3 megabits per second
    static constexpr unsigned long c_sendBitrateHd = 5 * 1024 * 1024; // 5 megabits per second
    static constexpr unsigned long c_sendBitrate4K = 25 * 1024 * 1024; // 25 megabits per second
    static constexpr unsigned long c_defaultBitrate = c_sendBitrateHd;
    static constexpr unsigned long c_defaultFramerate = 30;

    static constexpr unsigned short c_defaultPort = 8888;

    static constexpr unsigned long c_defaultPrePostRecvs = 1;

    static constexpr unsigned long c_defaultDuration = 60; // 1 minute

    static constexpr DWORD c_defaultSocketReceiveBufferSize = 1048576;

    // the address on which to listen (server only)
    ctl::ctSockaddr m_listenAddress{};

    // the target address to connect to (client only)
    ctl::ctSockaddr m_targetAddress{};

    // the list of interfaces to bind against (client only)
    std::vector<int> m_bindInterfaces{};

    // the port to use for connections
    unsigned short m_port = c_defaultPort;

    // the rate at which to send data (client only)
    unsigned long m_bitrate = c_defaultBitrate;

    // the number of frames to send per tick (client only)
    unsigned long m_framerate = c_defaultFramerate;

    // the number of receives to keep posted on the socket
    unsigned long m_prePostRecvs = c_defaultPrePostRecvs;

    // the duration to run the application, in seconds (client only)
    unsigned long m_duration = c_defaultDuration;

    // the file to output the results to (as csv)
    std::filesystem::path m_outputFile{};
};
} // namespace multipath