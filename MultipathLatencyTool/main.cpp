// ReSharper disable StringLiteralTypo
#include "adapters.h"
#include "config.h"
#include "logs.h"
#include "sockaddr.h"
#include "stream_client.h"
#include "stream_server.h"

#include <stdexcept>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <locale>

#include <Windows.h>
#include <winrt/Windows.Foundation.h>
#include <wlanapi.h>
#include <wil/result.h>
#include <wil/resource.h>

using namespace winrt;
using namespace Windows::Foundation;
using namespace multipath;

namespace {
template <typename T>
// ReSharper disable once CppInconsistentNaming
T integer_cast(const std::wstring_view)
{
    throw std::invalid_argument("invalid integral type");
}

template <>
long integer_cast<long>(const std::wstring_view str)
{
    long value = 0;
    size_t offset = 0;

    value = std::stol(std::wstring{str}, &offset, 10);

    if (offset != str.length())
    {
        throw std::invalid_argument("integer_cast: invalid input");
    }

    return value;
}

template <>
unsigned long integer_cast<unsigned long>(const std::wstring_view str)
{
    unsigned long value = 0;
    size_t offset = 0;
    value = std::stoul(std::wstring{str}, &offset, 10);

    if (offset != str.length())
    {
        throw std::invalid_argument("integer_cast: invalid input");
    }

    return value;
}

void PrintUsage()
{
    fwprintf(
        stdout,
        L"MultipathLatencyTool is a utility to compare the latencies of two network interfaces. "
        L"It is a client/server application that simply sends data at a given rate and echoes it back to the client. "
        L"It tracks the round-trip latency on each network interface and presents some basic statistics for the "
        L"session.\n"
        L"\nOnce started, Ctrl-C or Ctrl-Break will cleanly shutdown the application."
        L"\n\n"
        L"Server-side usage:\n"
        L"\tMultipathLatencyTool -listen:<addr or *> [-port:####] [-prepostrecvs:####]\n"
        L"\n"
        L"Client-side usage:\n"
        L"\tMultipathLatencyTool -target:<addr or name> [-port:####] [-bitrate:<see below>] [-framerate:<see below>] "
        L"[-duration:####] [-secondary:#] [-output:<path>]"
        L"[-prepostrecvs:####]\n"
        L"\n\n"
        L"---------------------------------------------------------\n"
        L"                      Common Options                     \n"
        L"---------------------------------------------------------\n"
        L"-port:####\n"
        L"\t- the port on which the server will listen and the client will connect\n"
        L"\t- (default value: 8888)\n"
        L"-prepostrecvs:####\n"
        L"\t- the number of receive requests to be kept in-flight\n"
        L"-help\n"
        L"\t- prints this usage information\n"
        L"\n\n"
        L"---------------------------------------------------------\n"
        L"                      Server Options                     \n"
        L"---------------------------------------------------------\n"
        L"-listen:<addr or *>\n"
        L"\t- the IP address on which the server will listen for incoming datagrams, or '*' for all addresses\n"
        L"\n\n"
        L"---------------------------------------------------------\n"
        L"                      Client Options                     \n"
        L"---------------------------------------------------------\n"
        L"-target:<addr or name>\n"
        L"\t- the IP address, FQDN, or hostname to connect to\n"
        L"-bitrate:<sd,hd,4k,##>\n"
        L"\t- the rate at which to send data; based on common video streaming rates:\n"
        L"\t\t- sd sends data at 3 megabits per second\n"
        L"\t\t- hd sends data at 5 megabits per second (default)\n"
        L"\t\t- 4k sends data at 25 megabits per second\n"
        L"\t\t- ## specifies the desired bitrate in magatbits per second\n"
        L"-framerate:####\n"
        L"\t- the number of frames to process during each send operation\n"
        L"-duration:####\n"
        L"\t- the total number of seconds to run (default: 60 seconds)\n"
        L"-secondary:<0,1>\n"
        L"\t- whether or not use a secondary wlan interface:\n"
        L"\t\t- set to 1 to make a best effort of using a secondary interface (default)\n"
        L"\t\t- set to 0 to not use a secondary interface. This can be used for comparison.\n"
        L"-output:<path>\n"
        L"\t- the path of a file where measured data will be stored\n");
}

std::wstring_view ParseArgumentValue(const std::wstring_view str)
{
    const auto delim = str.find(L':');
    if (delim == std::wstring_view::npos)
    {
        return {};
    }

    return str.substr(delim + 1);
}

std::optional<std::wstring_view> ParseArgument(const std::wstring_view name, std::vector<const wchar_t*>& args)
{
    auto foundParameter = std::ranges::find_if(args, [&](const std::wstring_view arg) { return arg.starts_with(name); });
    if (foundParameter != args.end())
    {
        auto value = ParseArgumentValue(*foundParameter);
        if (value.empty())
        {
            throw std::invalid_argument("Found parameter without value");
        }

        args.erase(foundParameter);
        return value;
    }
    return {};
}

Configuration ParseArguments(std::vector<const wchar_t*>& args)
{
    Configuration config;

    if (auto listenAddress = ParseArgument(L"-listen", args))
    {
        if (*listenAddress == L"*")
        {
            config.m_listenAddress = ctl::ctSockaddr(AF_INET, ctl::ctSockaddr::AddressType::Any);
        }
        else
        {
            auto resolvedAddresses = ctl::ctSockaddr::ResolveName(listenAddress->data());
            if (resolvedAddresses.empty())
            {
                throw std::invalid_argument("-listen parameter did not resolve to a valid address");
            }

            // just pick the first resolved address from the list
            config.m_listenAddress = resolvedAddresses.front();
        }
    }

    if (auto targetAddress = ParseArgument(L"-target", args))
    {
        if (config.m_listenAddress.family() != AF_UNSPEC)
        {
            throw std::invalid_argument("cannot specify both -listen and -target");
        }

        auto resolvedAddresses = ctl::ctSockaddr::ResolveName(targetAddress->data());
        if (resolvedAddresses.empty())
        {
            throw std::invalid_argument("-target parameter did not resolve to a valid address");
        }

        // just pick the first resolved address from the list
        // TODO: should try to determine which address(es) are actually reachable?
        config.m_targetAddress = resolvedAddresses.front();
    }

    if (config.m_listenAddress.family() == AF_UNSPEC && config.m_targetAddress.family() == AF_UNSPEC)
    {
        throw std::invalid_argument("-listen or -target must be specified");
    }

    if (auto port = ParseArgument(L"-port", args))
    {
        config.m_port = integer_cast<unsigned short>(*port);
    }

    if (auto bitrate = ParseArgument(L"-bitrate", args))
    {
        if (L"sd" == bitrate)
        {
            config.m_bitrate = Configuration::c_sendBitrateSd;
        }
        else if (L"hd" == bitrate)
        {
            config.m_bitrate = Configuration::c_sendBitrateHd;
        }
        else if (L"4k" == bitrate)
        {
            config.m_bitrate = Configuration::c_sendBitrate4K;
        }
        else if (L"test" == bitrate)
        {
            config.m_bitrate = Configuration::c_testSendBitrate;
        }
        else
        {
            // Convert from mb/s to b/s
            config.m_bitrate = integer_cast<unsigned long>(*bitrate) * 1024 * 1024;
        }
    }

    if (auto framerate = ParseArgument(L"-framerate", args))
    {
        config.m_framerate = integer_cast<unsigned long>(*framerate);
    }

    if (auto duration = ParseArgument(L"-duration", args))
    {
        config.m_duration = integer_cast<unsigned long>(*duration);
        if (config.m_duration < 1)
        {
            throw std::invalid_argument("-duration invalid argument");
        }
    }

    if (auto prepostRecvs = ParseArgument(L"-prepostrecvs", args))
    {
        config.m_prePostRecvs = integer_cast<unsigned long>(*prepostRecvs);
        if (config.m_prePostRecvs < 1)
        {
            throw std::invalid_argument("-prepostrecvs invalid argument");
        }
    }

    if (auto secondary = ParseArgument(L"-secondary", args))
    {
        config.m_useSecondaryWlanInterface = (integer_cast<unsigned long>(*secondary) != 0);
    }

    if (auto outputPath = ParseArgument(L"-output", args))
    {
        config.m_outputFile = *outputPath;

        std::filesystem::path filePath{config.m_outputFile};
        if (filePath.has_parent_path() && !std::filesystem::exists(filePath.parent_path()))
        {
            throw std::invalid_argument("-output invalid argument");
        }
    }

    // Undocumented options for debug purpose

    if (auto logLevel = ParseArgument(L"-loglevel", args))
    {
        SetLogLevel(static_cast<LogLevel>(integer_cast<unsigned long>(*logLevel)));
    }

    if (!args.empty())
    {
        throw std::invalid_argument("Unknown arguments");
    }

    return config;
}

void RunServerMode(Configuration& config)
{
    if (config.m_listenAddress.port() == 0)
    {
        config.m_listenAddress.SetPort(config.m_port);
    }

    Log<LogLevel::Output>("Starting the echo server...\n");

    StreamServer server(config.m_listenAddress);
    server.Start(config.m_prePostRecvs);

    Log<LogLevel::Output>("Ready to echo data\n");

    // Sleep until the program is interrupted with Ctrl-C
    Sleep(INFINITE);
}

void RunClientMode(Configuration& config)
{
    if (config.m_targetAddress.port() == 0)
    {
        config.m_targetAddress.SetPort(config.m_port);
    }

    // must have this handle open until we are done to keep the secondary STA port active
    wil::unique_wlan_handle wlanHandle;
    wil::unique_event completionEvent(wil::EventOptions::ManualReset);

    Log<LogLevel::Output>("Starting connection setup...\n");
    StreamClient client(config.m_targetAddress, config.m_prePostRecvs, completionEvent.get());
    if (config.m_useSecondaryWlanInterface)
    {
        client.RequestSecondaryWlanConnection();
    }

    Log<LogLevel::Output>("Start transmitting data...\n");
    client.Start(config.m_bitrate, config.m_framerate, config.m_duration);

    // wait for twice as long as the duration
    if (!completionEvent.wait(config.m_duration * 2 * 1000))
    {
        Log<LogLevel::Error>("Timed out waiting for run to complete\n");
        client.Stop();
    }

    Log<LogLevel::Output>("Transmission complete\n");
    client.PrintStatistics();

    if (!config.m_outputFile.empty())
    {
        Log<LogLevel::Output>("Dumping data to %s...\n", config.m_outputFile.filename().c_str());
        std::ofstream file{config.m_outputFile};
        client.DumpLatencyData(file);
        file.close();
    }
}

} // namespace

int __cdecl wmain(int argc, const wchar_t** argv)
try
{
    // Print wil logs to the standard error output
    wil::SetResultLoggingCallback([](wil::FailureInfo const& failure) noexcept {
        constexpr std::size_t sizeOfLogMessageWithNul = 2048;

        wchar_t logMessage[sizeOfLogMessageWithNul];
        wil::GetFailureLogString(logMessage, sizeOfLogMessageWithNul, failure);
        std::fputws(logMessage, stderr);
    });

    init_apartment();

    WSADATA wsadata{};
    int error = WSAStartup(WINSOCK_VERSION, &wsadata);
    if (ERROR_SUCCESS != error)
    {
        FAIL_FAST_WIN32_MSG(WSAGetLastError(), "WSAStartup failed");
    }

    if (argc < 2)
    {
        PrintUsage();
        return 0;
    }

    const wchar_t** argvBegin = argv + 1; // skip first argument (program name)
    const wchar_t** argvEnd = argv + argc;
    std::vector<const wchar_t*> args{argvBegin, argvEnd};

    auto foundHelp =
        std::ranges::find_if(args, [](const std::wstring_view arg) { return arg == L"-help" || arg == L"-?"; });
    if (foundHelp != args.end())
    {
        PrintUsage();
        return 0;
    }

    Configuration config = ParseArguments(args);

    if (config.m_listenAddress.family() != AF_UNSPEC)
    {
        // Start the server if "-listen" is specified
        std::cout << "--- Server Mode ---\n";
        std::wcout << L"Port: " << config.m_port << L'\n';
        std::wcout << L"Listen Address: " << config.m_listenAddress.WriteCompleteAddress() << L'\n';
        std::wcout << L"Number of receive buffers: " << config.m_prePostRecvs << L'\n';
        std::cout << "-------------------\n\n";

        RunServerMode(config);
    }
    else
    {
        // Start a client if "-target" is specified
        std::cout << "--- Client Mode ---\n";
        std::wcout << L"Port: " << config.m_port << L'\n';
        std::wcout << L"Target Address: " << config.m_targetAddress.WriteCompleteAddress() << L'\n';
        std::wcout << L"Stream Bitrate: " << config.m_bitrate << L" bits per second\n";
        std::wcout << L"Stream Framerate: " << config.m_framerate << L'\n';
        std::wcout << L"Stream Duration: " << config.m_duration << L" seconds\n";
        std::wcout << L"Number of receive buffers: " << config.m_prePostRecvs << L'\n';
        std::cout << "-------------------\n\n";

        RunClientMode(config);
    }
}
catch (const wil::ResultException& ex)
{
    std::cerr << "Caught exception: " << ex.what() << '\n';
    std::exit(-1);
}
catch (const std::invalid_argument& ex)
{
    std::cerr << "Invalid argument: " << ex.what() << '\n';
    std::exit(-1);
}
catch (const std::exception& ex)
{
    std::cerr << "Caught exception: " << ex.what() << '\n';
    std::exit(-1);
}
catch (...)
{
    std::cerr << "FATAL: UNHANDLED EXCEPTION";
    FAIL_FAST_MSG("FATAL: UNHANDLED EXCEPTION");
}