// ReSharper disable StringLiteralTypo
#include "adapters.h"
#include "config.h"
#include "debug.h"
#include "sockaddr.h"
#include "stream_client.h"
#include "stream_server.h"

#include <stdexcept>
#include <iostream>

#include <Windows.h>
#include <winrt/Windows.Foundation.h>
#include <wlanapi.h>
#include <wil/result.h>
#include <wil/resource.h>

using namespace winrt;
using namespace Windows::Foundation;
using namespace multipath;

namespace
{
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

        value = std::stol(std::wstring{ str }, &offset, 10);

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
        value = std::stoul(std::wstring{ str }, &offset, 10);

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
            L"\t- the number of frames to process during each send operation\n"
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

    const wchar_t** argvBegin = argv + 1; // skip first argument (program name)
    const wchar_t** argvEnd = argv + argc;
    std::vector<const wchar_t*> args{ argvBegin, argvEnd };

    auto foundHelp = std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-help") || StartsWith(arg, L"-?"); });
    if (foundHelp != args.end())
    {
        PrintUsage();
        return 0;
    }

    Configuration config;

    try
    {
        auto foundListen = std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-listen"); });
        if (foundListen != args.end())
        {
            auto value = ParseArgument(*foundListen);
            if (value.empty())
            {
                throw std::invalid_argument("-listen missing parameter");
            }
            else if (value == L"*")
            {
                config.m_listenAddress = ctl::ctSockaddr(AF_INET, ctl::ctSockaddr::AddressType::Any);
            }
            else
            {
                auto resolvedAddresses = ctl::ctSockaddr::ResolveName(value.data());
                if (resolvedAddresses.empty())
                {
                    throw std::invalid_argument("-listen parameter did not resolve to a valid address");
                }

                // just pick the first resolved address from the list
                config.m_listenAddress = resolvedAddresses.front();
            }

            args.erase(foundListen);
        }

        auto foundTarget = std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-target"); });
        if (foundTarget != args.end())
        {
            if (config.m_listenAddress.family() != AF_UNSPEC)
            {
                throw std::invalid_argument("cannot specify both -listen and -target");
            }

            auto value = ParseArgument(*foundTarget);
            if (value.empty())
            {
                throw std::invalid_argument("-target missing parameter");
            }

            auto resolvedAddresses = ctl::ctSockaddr::ResolveName(value.data());
            if (resolvedAddresses.empty())
            {
                throw std::invalid_argument("-target parameter did not resolve to a valid address");
            }

            // just pick the first resolved address from the list
            // TODO: should try to determine which address(es) are actually reachable?
            config.m_targetAddress = resolvedAddresses.front();

            args.erase(foundTarget);
        }

        auto foundPort = std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-port"); });
        if (foundPort != args.end())
        {
            auto value = ParseArgument(*foundPort);
            if (value.empty())
            {
                throw std::invalid_argument("-port missing parameter");
            }

            config.m_port = static_cast<unsigned short>(integer_cast<unsigned long>(value));

            args.erase(foundPort);
        }

        auto foundBitrate = std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-bitrate"); });
        if (foundBitrate != args.end())
        {
            auto value = ParseArgument(*foundBitrate);
            if (value.empty())
            {
                throw std::invalid_argument("-bitrate missing parameter");
            }

            if (L"sd" == value)
            {
                config.m_bitrate = Configuration::c_sendBitrateSd;
            }
            else if (L"hd" == value)
            {
                config.m_bitrate = Configuration::c_sendBitrateHd;
            }
            else if (L"4k" == value)
            {
                config.m_bitrate = Configuration::c_sendBitrate4K;
            }
            else if (L"test" == value)
            {
                config.m_bitrate = Configuration::c_testSendBitrate;
            }
            else
            {
                throw std::invalid_argument("-bitrate value must be one of: sd, hd, 4k");
            }

            args.erase(foundBitrate);
        }

        auto foundFramerate =
            std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-framerate"); });
        if (foundFramerate != args.end())
        {
            auto value = ParseArgument(*foundFramerate);
            if (value.empty())
            {
                throw std::invalid_argument("-framerate missing parameter");
            }

            config.m_framerate = integer_cast<unsigned long>(value);

            args.erase(foundFramerate);
        }

        auto foundDuration =
            std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-duration"); });
        if (foundDuration != args.end())
        {
            auto value = ParseArgument(*foundDuration);
            if (value.empty())
            {
                throw std::invalid_argument("-duration missing parameter");
            }

            config.m_duration = integer_cast<unsigned long>(value);
            if (config.m_duration < 1)
            {
                throw std::invalid_argument("-duration invalid argument");
            }

            args.erase(foundDuration);
        }

        auto foundPrePostRecvs =
            std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-prepostrecvs"); });
        if (foundPrePostRecvs != args.end())
        {
            auto value = ParseArgument(*foundPrePostRecvs);
            if (value.empty())
            {
                throw std::invalid_argument("-prepostrecvs missing parameter");
            }

            config.m_prePostRecvs = integer_cast<unsigned long>(value);
            if (config.m_prePostRecvs < 1)
            {
                throw std::invalid_argument("-prepostrecvs invalid argument");
            }

            args.erase(foundPrePostRecvs);
        }

        // Undocumented options for debug purpose
        auto foundConsoleVerbosity =
            std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-consoleverbosity"); });
        if (foundConsoleVerbosity != args.end())
        {
            auto value = ParseArgument(*foundConsoleVerbosity);
            if (value.empty())
            {
                throw std::invalid_argument("-consoleverbosity missing parameter");
            }

            SetConsoleVerbosity(integer_cast<unsigned long>(value));

            args.erase(foundConsoleVerbosity);
        }

        auto foundLocalDebug =
            std::ranges::find_if(args, [](const wchar_t* arg) { return StartsWith(arg, L"-localdebug"); });
        if (foundLocalDebug != args.end())
        {
            auto value = ParseArgument(*foundLocalDebug);
            if (value.empty())
            {
                throw std::invalid_argument("-localdebug missing parameter");
            }

            SetLocalDebugMode(integer_cast<unsigned long>(value) != 0);

            args.erase(foundLocalDebug);
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
        FAIL_FAST_MSG("UNHANDLED EXCEPTION");
    }

    std::cout << "--- Configuration ---\n";
    std::wcout << L"Port: " << config.m_port << L'\n';

    if (config.m_listenAddress.family() != AF_UNSPEC)
    {
        std::wcout << L"Listen Address: " << config.m_listenAddress.WriteCompleteAddress() << L'\n';
    }
    else
    {
        std::wcout << L"Target Address: " << config.m_targetAddress.WriteCompleteAddress() << L'\n';
        std::wcout << L"Stream Bitrate: " << config.m_bitrate << L"bits per second\n";
        std::wcout << L"Stream Framerate: " << config.m_framerate << L'\n';
        std::wcout << L"Stream Duration: " << config.m_duration << L" seconds\n";
    }

    std::wcout << L"PrePostRecvs: " << config.m_prePostRecvs << L'\n';

    try
    {
        if (config.m_listenAddress.family() != AF_UNSPEC)
        {
            if (config.m_listenAddress.port() == 0)
            {
                config.m_listenAddress.SetPort(config.m_port);
            }

            StreamServer server(config.m_listenAddress);

            server.Start(config.m_prePostRecvs);

            std::wcout << L"Listening for data...\n";

            // Sleep until the program is interrupted with Ctrl-C
            Sleep(INFINITE);
        }
        else
        {
            if (config.m_targetAddress.port() == 0)
            {
                config.m_targetAddress.SetPort(config.m_port);
            }

            if (!LocalDebugMode())
            {
                // must have this handle open until we are done to keep the second STA port active
                wil::unique_wlan_handle wlanHandle;

                DWORD clientVersion = 2; // Vista+ APIs
                DWORD curVersion = 0;
                error = WlanOpenHandle(clientVersion, nullptr, &curVersion, &wlanHandle);
                if (ERROR_SUCCESS != error)
                {
                    FAIL_FAST_WIN32_MSG(error, "WlanOpenHandle failed");
                }

                config.m_bindInterfaces = GetConnectedWlanInterfaces(wlanHandle.get());
            }
            else
            {
                // For debugging, use only the default interface
                config.m_bindInterfaces.push_back(0);
                config.m_bindInterfaces.push_back(0);
            }

            if (config.m_bindInterfaces.size() != 2)
            {
                throw std::runtime_error("two connected interfaces are required to run the client");
            }

            std::wcout << L"Bind Interfaces:\n";
            std::wcout << L'\t' << config.m_bindInterfaces[0] << L'\n';
            std::wcout << L'\t' << config.m_bindInterfaces[1] << L'\n';

            std::wcout << L"Starting connection setup...\n";
            wil::unique_event completeEvent(wil::EventOptions::ManualReset);
            StreamClient client(config.m_targetAddress, config.m_bindInterfaces[0], config.m_bindInterfaces[1], completeEvent.get());
            std::wcout << L"Start transmitting data...\n";
            client.Start(config.m_prePostRecvs, config.m_bitrate, config.m_framerate, config.m_duration);

            // wait for twice as long as the duration
            if (!completeEvent.wait(config.m_duration * 2 * 1000))
            {
                std::wcout << L"Timed out waiting for run to completion\n";
                client.Stop();
            }

            std::wcout << L"Transmission complete\n";
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
    catch (...)
    {
        FAIL_FAST_MSG("FATAL: UNHANDLED EXCEPTION");
    }
}
