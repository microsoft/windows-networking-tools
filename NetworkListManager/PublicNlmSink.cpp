// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <winsock2.h>
#include <windows.h>
#include <algorithm>
#include <wil/resource.h>
#include <wil/stl.h>
#include <wil/result.h>
#include <wil/result_macros.h>
#include "PublicNlmSink.h"

// INetworkEvents
IFACEMETHODIMP PublicNLMSink::NetworkAdded(GUID networkId) noexcept
try
{
    WCHAR* pNetworkId{nullptr};
    StringFromCLSID(networkId, &pNetworkId);
    std::wcout << wil::str_printf<std::wstring>(L"INetworkEvents::NetworkAdded : NetworkId %ws", pNetworkId) << std::endl;

    // Apps can call INetworkListManager::GetNetworks to re-enumerate networks.

    return S_OK;
}
CATCH_RETURN()

// INetworkEvents
IFACEMETHODIMP PublicNLMSink::NetworkDeleted(GUID networkId) noexcept
try
{
    WCHAR* pNetworkId{nullptr};
    StringFromCLSID(networkId, &pNetworkId);
    std::wcout << wil::str_printf<std::wstring>(L"INetworkEvents::NetworkDeleted : NetworkId %ws", pNetworkId) << std::endl;

    // Apps can call INetworkListManager::GetNetworks to re-enumerate networks.

    return S_OK;
}
CATCH_RETURN()

// INetworkEvents
IFACEMETHODIMP PublicNLMSink::NetworkConnectivityChanged(GUID networkId, NLM_CONNECTIVITY connectivity) noexcept
try
{
    WCHAR* pNetworkId{nullptr};
    StringFromCLSID(networkId, &pNetworkId);
    std::wcout << wil::str_printf<std::wstring>(
        L"INetworkEvents::NetworkConnectivityChanged : NetworkId %ws -- %ws",
        pNetworkId,
        Utility::ToString(connectivity).c_str()) << std::endl;

    // Apps can call INetwork::GetConnectivity to get the latest connectivity of the network.

    return S_OK;
}
CATCH_RETURN()

// INetworkEvents
IFACEMETHODIMP PublicNLMSink::NetworkPropertyChanged(GUID networkId, NLM_NETWORK_PROPERTY_CHANGE property) noexcept
try
{
    WCHAR* pNetworkId{nullptr};
    StringFromCLSID(networkId, &pNetworkId);
    std::wcout << wil::str_printf<std::wstring>(
        L"INetworkEvents::NetworkPropertyChanged : NetworkId %ws -- %ws",
        pNetworkId,
        Utility::ToString(property).c_str()) << std::endl;

    // Apps can query IPropertyBag interface to get the latest properties associated with the network.

    return S_OK;
}
CATCH_RETURN()

// INetworkConnectionEvents
IFACEMETHODIMP PublicNLMSink::NetworkConnectionConnectivityChanged(GUID connectionId, NLM_CONNECTIVITY connectivity) noexcept
try
{
    WCHAR* pConnectionIdId{nullptr};
    StringFromCLSID(connectionId, &pConnectionIdId);
    std::wcout << wil::str_printf<std::wstring>(
        L"INetworkConnectionEvents::NetworkConnectionConnectivityChanged : Connection %ws -- %ws",
        pConnectionIdId,
        Utility::ToString(connectivity).c_str()) << std::endl;

    // Apps can call INetworkConnection::GetConnectivity to get the latest connectivity of the network connection.

    return S_OK;
}
CATCH_RETURN()

// INetworkConnectionEvents
IFACEMETHODIMP PublicNLMSink::NetworkConnectionPropertyChanged(GUID connectionId, NLM_CONNECTION_PROPERTY_CHANGE property) noexcept
try
{
    WCHAR* pConnectionIdId{nullptr};
    StringFromCLSID(connectionId, &pConnectionIdId);
    std::wcout << wil::str_printf<std::wstring>(
        L"INetworkConnectionEvents::NetworkConnectionPropertyChanged : Connection %ws -- %ws",
        pConnectionIdId,
        Utility::ToString(property)) << std::endl;

    // Apps can call INetworkConnection2::IsDomainAuthenticatedBy to get the latest authentication (Domain Type) of this network connection.

    return S_OK;
}
CATCH_RETURN()

// INetworkConnectionCostEvents
IFACEMETHODIMP PublicNLMSink::ConnectionCostChanged(GUID connectionId, DWORD cost) noexcept
try
{
    WCHAR* pConnectionIdId{nullptr};
    StringFromCLSID(connectionId, &pConnectionIdId);
    std::wcout <<
        wil::str_printf<std::wstring>(
            L"INetworkConnectionCostEvents::ConnectionCostChanged : Connection %ws -- %ws",
            pConnectionIdId,
            Utility::ToString(static_cast<NLM_CONNECTION_COST>(cost)).c_str()) << std::endl;

    // Apps can call INetworkConnectionCost::GetCost to get the latest cost information associated with network connection.

    return S_OK;
}
CATCH_RETURN()

// INetworkConnectionCostEvents
IFACEMETHODIMP PublicNLMSink::ConnectionDataPlanStatusChanged(GUID connectionId) noexcept
try
{
    WCHAR* pConnectionIdId{nullptr};
    StringFromCLSID(connectionId, &pConnectionIdId);
    std::wcout <<
        wil::str_printf<std::wstring>(
            L"INetworkConnectionCostEvents::ConnectionDataPlanStatusChanged : Connection %ws",
            pConnectionIdId) << std::endl;

    // Apps can call INetworkConnectionCost::GetDataPlanStatus to get the latest data plan status associated with network connection.

    return S_OK;
}
CATCH_RETURN()

// INetworkListManagerEvents
IFACEMETHODIMP PublicNLMSink::ConnectivityChanged(NLM_CONNECTIVITY connectivity) noexcept
{
    std::wcout << wil::str_printf<std::wstring>(L"INetworkListManagerEvents::ConnectivityChanged : %ws", Utility::ToString(connectivity).c_str()) << std::endl;
    return S_OK;
}

// INetworkCostManagerEvents
IFACEMETHODIMP PublicNLMSink::CostChanged(DWORD cost, __RPC__in_opt NLM_SOCKADDR* pDestAddr) noexcept
try
{
    SOCKADDR_STORAGE sockAddrStorage{};
    if (pDestAddr)
    {
        memcpy(&sockAddrStorage, pDestAddr, sizeof(sockAddrStorage) > sizeof(*pDestAddr) ? sizeof(sockAddrStorage) : sizeof(*pDestAddr));
    }

    static const size_t SADDR_SIZE = sizeof(SOCKADDR_STORAGE);
    wchar_t buffer[256]{};
    DWORD bufferSize = sizeof(buffer);
    WSAAddressToStringW(reinterpret_cast<sockaddr*>(&sockAddrStorage), static_cast<DWORD>(SADDR_SIZE), nullptr, buffer, &bufferSize);

    std::wcout << wil::str_printf<std::wstring>(
            L"INetworkCostManagerEvents::CostChanged : Destination sockaddr '%ws' -- %ws",
            pDestAddr ? buffer : L"null",
            Utility::ToString(static_cast<NLM_CONNECTION_COST>(cost)).c_str()) << std::endl;

    // Apps can use INetworkListManager interface to query INetworkCostManager interface to get the latest machine-wide cost information.
    
    return S_OK;
}
CATCH_RETURN()

// INetworkCostManagerEvents
IFACEMETHODIMP PublicNLMSink::DataPlanStatusChanged(__RPC__in_opt NLM_SOCKADDR* pDestAddr) noexcept
try
{
    SOCKADDR_STORAGE sockAddrStorage{};
    if (pDestAddr)
    {
        memcpy(&sockAddrStorage, pDestAddr, sizeof(sockAddrStorage) > sizeof(*pDestAddr) ? sizeof(sockAddrStorage) : sizeof(*pDestAddr));
    }

    static const size_t SADDR_SIZE = sizeof(SOCKADDR_STORAGE);
    wchar_t buffer[256]{};
    DWORD bufferSize = sizeof(buffer);
    WSAAddressToStringW(reinterpret_cast<sockaddr*>(&sockAddrStorage), static_cast<DWORD>(SADDR_SIZE), nullptr, buffer, &bufferSize);

    std::wcout << wil::str_printf<std::wstring>(
        L"INetworkCostManagerEvents::DataPlanStatusChanged : Destination sockaddr '%ws' -- %ws",
        pDestAddr ? buffer : L"null") << std::endl;

    // Apps can use INetworkListManager interface to query INetworkCostManager interface to get the latest machine-wide data plan status.

    return S_OK;
}
CATCH_RETURN()
