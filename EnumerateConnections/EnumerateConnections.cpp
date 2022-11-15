// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Uses the TCPIP WMI interfaces to enumerate TCP and UDP connections
// Outputs information in csv format
// If run from a cmd shell, can redirect the output to a csv file and open in Excel for deeper analysis

#include <iostream>
#include <string>
#include <windows.h>
#include "wil/com.h"
#include "wil/stl.h"
#include "wil/resource.h"
#include "ctWmiInitialize.hpp"

PCSTR TcpStateToString(uint8_t state) noexcept
{
    switch (state)
    {
        case 1:
            return "Closed";
        case 2:
            return "Listen";
        case 3:
            return "SynSent";
        case 4:
            return "SynReceived";
        case 5:
            return "Established";
        case 6:
            return "FinWait1";
        case 7:
            return "FinWait2";
        case 8:
            return "CloseWait";
        case 9:
            return "Closing";
        case 10:
            return "LastAck";
        case 11:
            return "TimeWait";
        case 12:
            return "DeleteTCB";
        case 100:
            return "Bound";
        default:
            WI_ASSERT(false);
            return "<unknown state>";
    }
}

std::wstring PidToString(uint32_t pid)
{
    if (pid == 0 || pid == 4)
    {
        return L"<system process>";
    }

    const wil::unique_handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process)
    {
        const auto gle = GetLastError();
        if (gle == ERROR_ACCESS_DENIED)
        {
            return L"<failed to open process: access denied";
        }
        return wil::str_printf<std::wstring>(L"<failed to open process: %d>", gle);
    }

    DWORD processNameSize = MAX_PATH;
    std::wstring processName(processNameSize, L'\0');
    if (!QueryFullProcessImageName(process.get(), 0, processName.data(), &processNameSize))
    {
        const auto gle = GetLastError();
        return wil::str_printf<std::wstring>(L"<failed to query process: %d>", gle);
    }

    processName.resize(processNameSize);
    return processName;
}

int main()
try
{
    const auto comInit = wil::CoInitializeEx();
    const auto wmiService = ctl::ctWmiService(L"root\\standardcimv2");
    auto wmiEnumerator = ctl::ctWmiEnumerate(wmiService);

    printf("EndpointAddress,TcpState,ProcessId,ProcessImageName\n");
    for (const auto& instance : wmiEnumerator.query(L"SELECT * FROM MSFT_NetTcpConnection"))
    {
        uint32_t pid{};
        instance.get(L"OwningProcess", &pid);
        std::wstring localAddress;
        instance.get(L"LocalAddress", &localAddress);
        uint32_t localPort{};
        instance.get(L"LocalPort", &localPort);
        std::wstring remoteAddress;
        instance.get(L"RemoteAddress", &remoteAddress);
        uint32_t remotePort{};
        instance.get(L"RemotePort", &remotePort);
        uint8_t state{};
        instance.get(L"State", &state);

        printf("[%ws:%u - %ws:%u],%hs,%d,%ws\n", localAddress.c_str(), localPort, remoteAddress.c_str(), remotePort, TcpStateToString(state), pid, PidToString(pid).c_str());
    }

    for (const auto& instance : wmiEnumerator.query(L"SELECT * FROM MSFT_NetUDPEndpoint"))
    {
        uint32_t pid{};
        instance.get(L"OwningProcess", &pid);
        std::wstring localAddress;
        instance.get(L"LocalAddress", &localAddress);
        uint32_t localPort{};
        instance.get(L"LocalPort", &localPort);

        printf("%ws:%u,,%d,%ws\n", localAddress.c_str(), localPort, pid, PidToString(pid).c_str());
    }
    return 0;
}
CATCH_RETURN()
