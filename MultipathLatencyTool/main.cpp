#include "pch.h"

#include "adapters.h"
#include "config.h"
#include "sockaddr.h"
#include "stream_client.h"
#include "stream_server.h"

using namespace winrt;
using namespace Windows::Foundation;

using namespace multipath;

namespace {
template <typename T>
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
        L"It tracks the round-trip latency on each network interface and presents some basic statistics for the session.\n"
        L"\nOnce started, Ctrl-C or Ctrl-Break will cleanly shutdown the application."
        L"\n\n"
        L"Server-side usage:\n"
        L"\tMultipathLatencyTool -listen:<addr or *> [-port:####] [-prepostrecvs:####]\n"
        L"\n"
        L"Client-side usage:\n"
        L"\tMultipathLatencyTool -target:<addr or name> [-port:####] [-rate:<see below>] [-duration:####] [-prepostrecvs:####]\n"
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
        L"\t- the number of frames to send during each send operation\n"
        L"-duration:####\n"
        L"\t- the total number of seconds to run (default: 60 seconds)\n");
}

// implementation of C++20's std::wstring_view::starts_with
[[nodiscard]] bool StartsWith(const std::wstring_view str, const std::wstring_view prefix) noexcept
{
    if (str.size() < prefix.size())
    {
        return false;
    }

    return std::wstring_view::traits_type::compare(str.data(), prefix.data(), prefix.size()) == 0;
}

std::wstring_view ParseArgument(const std::wstring_view str)
{
    const auto delim = str.find(L':');
    if (delim == std::wstring_view::npos)
    {
        return {};
    }

    return str.substr(delim + 1);
}
} // namespace

int __cdecl wmain(int argc, const wchar_t** argv)
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

    const wchar_t** argv_begin = argv + 1; // skip first argument (program name)
    const wchar_t** argv_end = argv + argc;
    std::vector<const wchar_t*> args{argv_begin, argv_end};

    auto foundHelp = std::find_if(
        args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-help") || StartsWith(arg, L"-?"); });
    if (foundHelp != args.end())
    {
        PrintUsage();
        return 0;
    }

    Configuration config;

    try
    {
        auto foundListen = std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-listen"); });
        if (foundListen != args.end())
        {
            auto value = ParseArgument(*foundListen);
            if (value.empty())
            {
                throw std::invalid_argument("-listen missing parameter");
            }
            else if (value == L"*")
            {
                config.listenAddress = Sockaddr(AF_INET, Sockaddr::AddressType::Any);
            }
            else
            {
                auto resolvedAddresses = Sockaddr::ResolveName(value.data());
                if (resolvedAddresses.empty())
                {
                    throw std::invalid_argument("-listen parameter did not resolve to a valid address");
                }

                // just pick the first resolved address from the list
                config.listenAddress = resolvedAddresses.front();
            }

            args.erase(foundListen);
        }

        auto foundTarget = std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-target"); });
        if (foundTarget != args.end())
        {
            if (config.listenAddress)
            {
                throw std::invalid_argument("cannot specify both -listen and -target");
            }

            auto value = ParseArgument(*foundTarget);
            if (value.empty())
            {
                throw std::invalid_argument("-target missing parameter");
            }

            auto resolvedAddresses = Sockaddr::ResolveName(value.data());
            if (resolvedAddresses.empty())
            {
                throw std::invalid_argument("-target parameter did not resolve to a valid address");
            }

            // just pick the first resolved address from the list
            // TODO: should try to determine which address(es) are actually reachable?
            config.targetAddress = resolvedAddresses.front();

            args.erase(foundTarget);
        }

        auto foundPort = std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-port"); });
        if (foundPort != args.end())
        {
            auto value = ParseArgument(*foundPort);
            if (value.empty())
            {
                throw std::invalid_argument("-port missing parameter");
            }

            config.port = static_cast<unsigned short>(integer_cast<unsigned long>(value));

            args.erase(foundPort);
        }

        auto foundBitrate = std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-bitrate"); });
        if (foundBitrate != args.end())
        {
            auto value = ParseArgument(*foundBitrate);
            if (value.empty())
            {
                throw std::invalid_argument("-bitrate missing parameter");
            }

            if (L"sd" == value)
            {
                config.bitrate = Configuration::SendBitrateSd;
            }
            else if (L"hd" == value)
            {
                config.bitrate = Configuration::SendBitrateHd;
            }
            else if (L"4k" == value)
            {
                config.bitrate = Configuration::SendBitrate4k;
            }
            else
            {
                throw std::invalid_argument("-bitrate value must be one of: sd, hd, 4k");
            }

            args.erase(foundBitrate);
        }

        auto foundFramerate =
            std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-framerate"); });
        if (foundFramerate != args.end())
        {
            auto value = ParseArgument(*foundFramerate);
            if (value.empty())
            {
                throw std::invalid_argument("-framerate missing parameter");
            }

            config.framerate = integer_cast<unsigned long>(value);

            args.erase(foundFramerate);
        }

        auto foundDuration =
            std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-duration"); });
        if (foundDuration != args.end())
        {
            auto value = ParseArgument(*foundDuration);
            if (value.empty())
            {
                throw std::invalid_argument("-duration missing parameter");
            }

            config.duration = integer_cast<unsigned long>(value);

            args.erase(foundDuration);
        }

        auto foundPrePostRecvs =
            std::find_if(args.begin(), args.end(), [](const wchar_t* arg) { return StartsWith(arg, L"-prepostrecvs"); });
        if (foundPrePostRecvs != args.end())
        {
            auto value = ParseArgument(*foundPrePostRecvs);
            if (value.empty())
            {
                throw std::invalid_argument("-prepostrecvs missing paramter");
            }

            config.prePostRecvs = integer_cast<unsigned long>(value);

            args.erase(foundPrePostRecvs);
        }

        // get connected interfaces
        config.bindInterfaces = GetConnectedInterfaces();
    }
    catch (const wil::ResultException& ex)
    {
        std::cerr << "Caught exception: " << ex.what() << '\n';
    }
    catch (const std::invalid_argument& ex)
    {
        std::cerr << "Invalid argument: " << ex.what() << '\n';
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Caught exception: " << ex.what() << '\n';
    }
    catch (...)
    {
        FAIL_FAST_MSG("UNHANDLED EXCEPTION");
    }

    std::cout << "--- Configuration ---\n";
    std::wcout << L"Listen Address: " << config.listenAddress.write_complete_address() << L'\n';
    std::wcout << L"Target Address: " << config.targetAddress.write_complete_address() << L'\n';
    std::wcout << L"Bind Interfaces: ";
    for (const auto& ifIndex : config.bindInterfaces)
    {
        std::wcout << ifIndex << L' ';
    }
    std::wcout << L'\n';

    try
    {
        if (config.listenAddress)
        {
            if (config.listenAddress.port() == 0)
            {
                config.listenAddress.set_port(config.port);
            }

            StreamServer server(config.listenAddress);

            server.Start(config.prePostRecvs);

            for (;;)
            {
            }
        }
        else
        {
            if (config.targetAddress.port() == 0)
            {
                config.targetAddress.set_port(config.port);
            }

            if (config.bindInterfaces.size() != 2)
            {
                throw std::runtime_error("two connected interfaces are required to run the client");
            }

            wil::unique_event completeEvent(wil::EventOptions::ManualReset);

            StreamClient client(config.targetAddress, config.bindInterfaces[0], config.bindInterfaces[1], completeEvent.get());
            client.Start(config.prePostRecvs, config.bitrate, config.framerate, config.duration);
            
            if (!completeEvent.wait(30 * 1000))
            {
                // timed out waiting for the run to complete
                client.Stop();
            }

            client.PrintStatistics();
        }
    }
    catch (const wil::ResultException& ex)
    {
        std::cout << "Caught exception: " << ex.what() << '\n';
    }
    catch (const std::exception& ex)
    {
        std::cout << "Caught exception: " << ex.what() << '\n';
    }
}
