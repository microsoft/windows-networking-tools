// ReSharper disable StringLiteralTypo
#include "adapters.h"
#include "config.h"
#include "debug.h"
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
        L"\tMultipathLatencyTool -target:<addr or name> [-port:####] [-rate:<see below>] [-duration:####] "
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
        L"-bitrate:<sd,hd,4k>\n"
        L"\t- the rate at which to send data; based on common video streaming rates:\n"
        L"\t\t- sd sends data at 3 megabits per second\n"
        L"\t\t- hd sends data at 5 megabits per second (default)\n"
        L"\t\t- 4k sends data at 25 megabits per second\n"
        L"-framerate:####\n"
        L"\t- the number of frames to process during each send operation\n"
        L"-duration:####\n"
        L"\t- the total number of seconds to run (default: 60 seconds)\n"
        L"-secondary:<enforce,besteffort,ignore>\n"
        L"\t- whether or not use a secondary wlan interface:\n"
        L"\t\t- enforce uses a secondary interface or fails if it cannot\n"
        L"\t\t    for test or debugging purpose"
        L"\t\t- besteffort use the secondary interface if possible (default)\n"
        L"\t\t    this is what most applications should do"
        L"\t\t- ignore doesn't use a secondary interface. This can be used for comparison.\n"
        L"-output:####\n"
        L"\t- the path of the file where to output measured data\n");
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
            throw std::invalid_argument("-bitrate value must be one of: sd, hd, 4k, test");
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

    if (auto prepostRecvs = ParseArgument(L"-prepostrecvs" , args))
    {
        config.m_prePostRecvs = integer_cast<unsigned long>(*prepostRecvs);
        if (config.m_prePostRecvs < 1)
        {
            throw std::invalid_argument("-prepostrecvs invalid argument");
        }
    }

    if (auto secondary = ParseArgument(L"-secondary", args))
    {
        if (L"enforce" == secondary)
        {
            config.m_secondaryInterfaceBehavior = Configuration::SecondaryInterfaceBehavior::Enforce;
        }
        else if (L"besteffort" == secondary)
        {
            config.m_secondaryInterfaceBehavior = Configuration::SecondaryInterfaceBehavior::BestEffort;
        }
        else if (L"ignore" == secondary)
        {
            config.m_secondaryInterfaceBehavior = Configuration::SecondaryInterfaceBehavior::Ignore;
        }
        else
        {
            throw std::invalid_argument("-secondary value must be one of: enforce, besteffort, ignore");
        }
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

    // Set to 2 for debug logs
    if (auto consoleVerbosity = ParseArgument(L"-consoleVerbosity", args))
    {
        SetConsoleVerbosity(integer_cast<unsigned long>(*consoleVerbosity));
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

    std::wcout << L"Starting the echo server...\n";

    StreamServer server(config.m_listenAddress);
    server.Start(config.m_prePostRecvs);

    std::wcout << L"Listening for data...\n";

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
    constexpr int primaryInterface = 0;
    std::optional<int> secondaryInterface{};

    if (config.m_secondaryInterfaceBehavior != Configuration::SecondaryInterfaceBehavior::Ignore)
    {
        DWORD clientVersion = 2; // Vista+ APIs
        DWORD curVersion = 0;
        auto error = WlanOpenHandle(clientVersion, nullptr, &curVersion, &wlanHandle);
        FAIL_FAST_IF_WIN32_ERROR_MSG(error, "WlanOpenHandle failed");

        secondaryInterface = GetSecondaryInterfaceBestEffort(wlanHandle.get());

        if (config.m_secondaryInterfaceBehavior == Configuration::SecondaryInterfaceBehavior::Enforce &&
            !secondaryInterface)
        {
            throw std::runtime_error("Two connected interfaces are required to run the client");
        }

        if (secondaryInterface)
        {
            std::cout << "Using secondary interface, index: " << *secondaryInterface << std::endl;
        }
    }

    std::wcout << L"Starting connection setup...\n";
    StreamClient client(config.m_targetAddress, primaryInterface, secondaryInterface, completionEvent.get());

    std::wcout << L"Start transmitting data...\n";
    client.Start(config.m_prePostRecvs, config.m_bitrate, config.m_framerate, config.m_duration);

    // wait for twice as long as the duration
    if (!completionEvent.wait(config.m_duration * 2 * 1000))
    {
        std::wcout << L"Timed out waiting for run to completion\n";
        client.Stop();
    }

    std::wcout << L"Transmission complete\n";
    client.PrintStatistics();

    if (!config.m_outputFile.empty())
    {
        std::wcout << L"Dumping data to " << config.m_outputFile << "\n";
        std::ofstream file{config.m_outputFile};
        client.DumpLatencyData(file);
        file.close();
    }
}

} // namespace

int __cdecl wmain(int argc, const wchar_t** argv)
try
{
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

    std::cout << "--- Configuration ---\n";
    std::wcout << L"Port: " << config.m_port << L'\n';

    if (config.m_listenAddress.family() != AF_UNSPEC)
    {
        std::wcout << L"Listen Address: " << config.m_listenAddress.WriteCompleteAddress() << L'\n';
    }
    else
    {
        std::wcout << L"Target Address: " << config.m_targetAddress.WriteCompleteAddress() << L'\n';
        std::wcout << L"Stream Bitrate: " << config.m_bitrate << L" bits per second\n";
        std::wcout << L"Stream Framerate: " << config.m_framerate << L'\n';
        std::wcout << L"Stream Duration: " << config.m_duration << L" seconds\n";
    }

    std::wcout << L"Number of receive buffers: " << config.m_prePostRecvs << L'\n';

    if (config.m_listenAddress.family() != AF_UNSPEC)
    {
        // Start the server if "-listen" is specified
        RunServerMode(config);
    }
    else
    {
        // Start a client if "-target" is specified
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