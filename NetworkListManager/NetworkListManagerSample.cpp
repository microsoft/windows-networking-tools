// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rpc.h>
#include <rpcasync.h>
#include <wil/com.h>
#include <wil/result.h>
#include <wil/result_macros.h>
#include "NetworkListManagerSample.h"
#include "PublicNetworkListManager.h"
#include "PublicNlmSink.h"

int __cdecl wmain()
try
{
    auto coinit = wil::CoInitializeEx_failfast(COINIT_MULTITHREADED);
    WSADATA wsaData{};
    THROW_IF_WIN32_ERROR(WSAStartup(MAKEWORD(2, 2), &wsaData));

    auto wsaCleanup = wil::scope_exit([] {
        WSACleanup();
    });

    PublicNlm publicNlm;
    std::wstring outputString;
    outputString += L"******************** INetworkListManager GetConnectivity ********************\n";
    outputString += publicNlm.GetConnectivity();
    outputString += L"******************** INetworkListManager GetNetworkConnections ********************\n";
    outputString += publicNlm.GetNetworkConnections();
    outputString += L"******************** INetworkListManager GetNetworks(NLM_ENUM_NETWORK_ALL) ********************\n";
    outputString += publicNlm.GetNetworks(NLM_ENUM_NETWORK_ALL);
    outputString += L"******************** INetworkListManager GetNetworks(NLM_ENUM_NETWORK_CONNECTED) ********************\n";
    outputString += publicNlm.GetNetworks(NLM_ENUM_NETWORK_CONNECTED);
    outputString += L"******************** INetworkListManager GetNetworkConnectionCost ********************\n";
    outputString += publicNlm.GetNetworkConnectionCost();
    outputString += L"******************** INetworkListManager GetNetworkCost ********************\n";
    outputString += publicNlm.GetNetworkCost();

    outputString += L"******************** Registering to all INetworkListManager event notifications ********************\n";
    outputString += L"   Press any key to stop  \n";
    publicNlm.TryStartEventNotifications();
    std::wcout << outputString << std::endl;
    static_cast<void>(getchar());
    return 0;
}
CATCH_RETURN()
