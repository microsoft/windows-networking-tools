// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <winsock2.h>
#include <windows.h>
#include <netiodef.h>
#include <wil/resource.h>
#include <wil/stl.h>
#include <ws2tcpip.h>
#include <wrl/client.h>
#include <wil/result.h>
#include <wil/result_macros.h>
#include "PublicNetworkListManager.h"

using namespace Microsoft::WRL;

std::wstring ToStringCheckingErrors(const std::wstring& errorString, const std::wstring& dataString)
{
    return errorString.empty() ? dataString : errorString;
}

PublicNlm::PublicNlm()
{
    THROW_IF_FAILED(
        ::CoCreateInstance(
            __uuidof(NetworkListManager),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetworkListManager),
            reinterpret_cast<void**>(m_netListManager.GetAddressOf())));
}

void PublicNlm::TryStartEventNotifications()
{
    const auto lock = m_sinkLock.try_lock();
    if (lock)
    {
        if (!m_connectionSink)
        {
            m_connectionSink = Make<PublicNLMSink>();

            m_publicNlmEvents.AdviseInProcObject<INetworkEvents>(m_netListManager, m_connectionSink.Get());
            m_publicNlmEvents.AdviseInProcObject<INetworkListManagerEvents>(m_netListManager, m_connectionSink.Get());
            m_publicNlmEvents.AdviseInProcObject<INetworkCostManagerEvents>(m_netListManager, m_connectionSink.Get());
            m_publicNlmEvents.AdviseInProcObject<INetworkConnectionEvents>(m_netListManager, m_connectionSink.Get());
            m_publicNlmEvents.AdviseInProcObject<INetworkConnectionCostEvents>(m_netListManager, m_connectionSink.Get());
        }
    }
}

// GetConnectivity returns machine level connectivity via ipv4 or ipv6 or both.
std::wstring PublicNlm::GetConnectivity() const
{
    // Apps and services calling GetConnectivity should try to connect to their server if the api returns one of the following:
    // NLM_CONNECTIVITY_IPV4_LOCALNETWORK, NLM_CONNECTIVITY_IPV4_INTERNET, NLM_CONNECTIVITY_IPV6_LOCALNETWORK, NLM_CONNECTIVITY_IPV6_INTERNET
    NLM_CONNECTIVITY nlmConnectivity{NLM_CONNECTIVITY_DISCONNECTED};
    THROW_IF_FAILED(m_netListManager->GetConnectivity(&nlmConnectivity));

    // get_IsConnected returns if the machine has at least local connectivity via ipv4 or ipv6 or both.
    VARIANT_BOOL isConnected{FALSE};
    THROW_IF_FAILED(m_netListManager->get_IsConnected(&isConnected));

    // get_IsConnectedToInternet returns if the machine is connected to internet via ipv4 or ipv6 or both.
    VARIANT_BOOL isConnectedToInternet{FALSE};
    THROW_IF_FAILED(m_netListManager->get_IsConnectedToInternet(&isConnectedToInternet));

    return Utility::PrintInstanceHeader(L"NLM_CONNECTIVITY") +
        wil::str_printf<std::wstring>(
            L"  > Connectivity: %ws\n"
            L"  > IsConnected: %ws\n"
            L"  > IsConnectedToInternet: %ws\n",
            Utility::ToString(nlmConnectivity).c_str(),
            !!isConnected ? L"True" : L"False",
            !!isConnectedToInternet ? L"True" : L"False") +
        Utility::PrintInstanceFooter();
}

// NetworkListManager as INetworkCostManager to query machine-wide cost and data plan status information associated with
// a connection used for machine-wide Internet connectivity.
std::wstring PublicNlm::GetNetworkCost() const
{
    ComPtr<INetworkCostManager> netCostManager;
    THROW_IF_FAILED(m_netListManager.As<INetworkCostManager>(&netCostManager));

    std::wstring outputString(Log(netCostManager.Get()));
    outputString += L"\n";

    return outputString;
}

// Enumerate cost and data plan status information associated with each network connection.
std::wstring PublicNlm::GetNetworkConnectionCost() const
{
    std::wstring outputString;
    ComPtr<IEnumNetworkConnections> enumNetworkConnections;
    THROW_IF_FAILED(m_netListManager->GetNetworkConnections(enumNetworkConnections.GetAddressOf()));

    bool insertEmptyLine{false};
    for (auto hr = S_OK; hr == S_OK;)
    {
        ULONG fetched{0};
        ComPtr<INetworkConnection> networkConnection;
        THROW_IF_FAILED(hr = enumNetworkConnections->Next(1, networkConnection.GetAddressOf(), &fetched));
        if (hr == S_OK)
        {
            ComPtr<INetworkConnectionCost> networkConnectionCost;
            THROW_IF_FAILED(
                networkConnection.As<INetworkConnectionCost>(&networkConnectionCost));
            if (insertEmptyLine)
            {
                outputString += L"\n";
            }
            outputString += Log(networkConnectionCost.Get());
            insertEmptyLine = true;
        }
    }

    return outputString;
}

// GetNetworkConnections enumerates all network connections on the machine, including wifi, cellular, ethernet, etc.
// Apps can then query properties for individual network connection.
std::wstring PublicNlm::GetNetworkConnections() const
{
    std::wstring outputString;
    ComPtr<IEnumNetworkConnections> enumNetworkConnections;
    THROW_IF_FAILED(m_netListManager->GetNetworkConnections(enumNetworkConnections.GetAddressOf()));

    bool insertEmptyLine{false};
    for (auto hr = S_OK; hr == S_OK;)
    {
        ULONG fetched{0};
        ComPtr<INetworkConnection> networkConnection;
        THROW_IF_FAILED(hr = enumNetworkConnections->Next(1, networkConnection.GetAddressOf(), &fetched));
        if (hr == S_OK)
        {
            if (insertEmptyLine)
            {
                outputString += L"\n";
            }
            outputString += Log(networkConnection.Get());
            insertEmptyLine = true;
        }
    }

    return outputString;
}

// GetNetworkConnections enumerates list of networks available on the machine, including wifi, cellular, ethernet, etc.
// Apps can then query properties for individual network.
// Apps can specify a NLM_ENUM_NETWORK flag to query only certain networks.
std::wstring PublicNlm::GetNetworks(const NLM_ENUM_NETWORK networkEnum) const
{
    std::wstring outputString;
    ComPtr<IEnumNetworks> enumConnectedNetworks;
    THROW_IF_FAILED(m_netListManager->GetNetworks(networkEnum, enumConnectedNetworks.GetAddressOf()));

    bool insertEmptyLine{false};
    for (auto hr = S_OK; hr == S_OK;)
    {
        ULONG fetched{0};
        ComPtr<INetwork> network;
        THROW_IF_FAILED(hr = enumConnectedNetworks->Next(1, network.GetAddressOf(), &fetched));
        if (hr == S_OK)
        {
            if (insertEmptyLine)
            {
                outputString += L"\n";
            }
            outputString += Log(network.Get());
            insertEmptyLine = true;
        }
    }

    return outputString;
}

static std::wstring LogINetworkConnection2(_In_ INetworkConnection2* const pNetworkConnection2)
{
    std::wstring isDomainAuthenticatedByNoneError;
    BOOL isDomainAuthenticatedByNone{FALSE};
    if (const auto error =
        FAILED(pNetworkConnection2->IsDomainAuthenticatedBy(NLM_DOMAIN_AUTHENTICATION_KIND_NONE, &isDomainAuthenticatedByNone)))
    {
        isDomainAuthenticatedByNoneError =
            wil::str_printf<std::wstring>(L"  ! <INetworkConnection2::IsDomainAuthenticatedBy(None) failed (0x%x)>", error);
    }
    std::wstring isDomainAuthenticatedByNoneString = !!isDomainAuthenticatedByNone ? L"true" : L"false";

    std::wstring isDomainAuthenticatedByLdapError;
    BOOL isDomainAuthenticatedByLdap{FALSE};
    if (const auto error =
        FAILED(pNetworkConnection2->IsDomainAuthenticatedBy(NLM_DOMAIN_AUTHENTICATION_KIND_LDAP, &isDomainAuthenticatedByLdap)))
    {
        isDomainAuthenticatedByLdapError =
            wil::str_printf<std::wstring>(L"  ! <INetworkConnection2::IsDomainAuthenticatedBy(Ldap) failed (0x%x)>", error);
    }
    std::wstring isDomainAuthenticatedByLdapString = !!isDomainAuthenticatedByLdap ? L"true" : L"false";

    std::wstring isDomainAuthenticatedByTlsError;
    BOOL isDomainAuthenticatedByTls{FALSE};
    if (const auto error =
        FAILED(pNetworkConnection2->IsDomainAuthenticatedBy(NLM_DOMAIN_AUTHENTICATION_KIND_TLS, &isDomainAuthenticatedByTls)))
    {
        isDomainAuthenticatedByTlsError =
            wil::str_printf<std::wstring>(L"  ! <INetworkConnection2::IsDomainAuthenticatedBy(Tls) failed (0x%x)>", error);
    }
    std::wstring isDomainAuthenticatedByTlsString = !!isDomainAuthenticatedByTls ? L"true" : L"false";

    return Utility::PrintInstanceHeader(L"INetworkConnection2 object") +
        wil::str_printf<std::wstring>(
            L"    IsDomainAuthenticatedBy(None): %ws\n"
            L"    IsDomainAuthenticatedBy(Ldap): %ws\n"
            L"    IsDomainAuthenticatedBy(Tls): %ws\n",
            ToStringCheckingErrors(isDomainAuthenticatedByNoneError, isDomainAuthenticatedByNoneString).c_str(),
            ToStringCheckingErrors(isDomainAuthenticatedByLdapError, isDomainAuthenticatedByLdapString).c_str(),
            ToStringCheckingErrors(isDomainAuthenticatedByTlsError, isDomainAuthenticatedByTlsString).c_str()) +
        Utility::PrintInstanceFooter();
}

std::wstring PublicNlm::Log(_In_ INetworkConnection* pNetworkConnection) const
{
    GUID adapterId{};
    THROW_IF_FAILED(pNetworkConnection->GetAdapterId(&adapterId));

    GUID connectionId{};
    THROW_IF_FAILED(pNetworkConnection->GetConnectionId(&connectionId));

    NLM_CONNECTIVITY nlmConnectivity{NLM_CONNECTIVITY_DISCONNECTED};
    THROW_IF_FAILED(pNetworkConnection->GetConnectivity(&nlmConnectivity));

    NLM_DOMAIN_TYPE nlmDomainType{NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK};
    THROW_IF_FAILED(pNetworkConnection->GetDomainType(&nlmDomainType));

    std::wstring networkConnection2String;
    ComPtr<INetworkConnection2> networkConnection2;
    const auto hr = pNetworkConnection->QueryInterface(networkConnection2.GetAddressOf());
    if (FAILED(hr))
    {
        networkConnection2String =
            wil::str_printf<std::wstring>(L"  ! <INetworkConnection::QueryInterface(INetworkConnenction2) failed (0x%x)>", hr);
    }

    if (networkConnection2)
    {
        networkConnection2String.push_back(L'\n');
        networkConnection2String.append(LogINetworkConnection2(networkConnection2.Get()));
    }

    return networkConnection2String;
}

static std::wstring LogINetwork2(_In_ INetwork2* const pNetwork2)
{
    std::wstring isDomainAuthenticatedByNoneError;
    BOOL isDomainAuthenticatedByNone{FALSE};
    if (const auto error = FAILED(pNetwork2->IsDomainAuthenticatedBy(NLM_DOMAIN_AUTHENTICATION_KIND_NONE, &isDomainAuthenticatedByNone)))
    {
        isDomainAuthenticatedByNoneError =
            wil::str_printf<std::wstring>(L"  ! <INetwork2::IsDomainAuthenticatedBy(None) failed (0x%x)>", error);
    }
    std::wstring isDomainAuthenticatedByNoneString = !!isDomainAuthenticatedByNone ? L"true" : L"false";

    std::wstring isDomainAuthenticatedByLdapError;
    BOOL isDomainAuthenticatedByLdap{FALSE};
    if (const auto error = FAILED(pNetwork2->IsDomainAuthenticatedBy(NLM_DOMAIN_AUTHENTICATION_KIND_LDAP, &isDomainAuthenticatedByLdap)))
    {
        isDomainAuthenticatedByLdapError =
            wil::str_printf<std::wstring>(L"  ! <INetwork2::IsDomainAuthenticatedBy(Ldap) failed (0x%x)>", error);
    }
    std::wstring isDomainAuthenticatedByLdapString = !!isDomainAuthenticatedByLdap ? L"true" : L"false";

    std::wstring isDomainAuthenticatedByTlsError;
    BOOL isDomainAuthenticatedByTls{FALSE};
    if (const auto error = FAILED(pNetwork2->IsDomainAuthenticatedBy(NLM_DOMAIN_AUTHENTICATION_KIND_TLS, &isDomainAuthenticatedByTls)))
    {
        isDomainAuthenticatedByTlsError =
            wil::str_printf<std::wstring>(L"  ! <INetwork2::IsDomainAuthenticatedBy(Tls) failed (0x%x)>", error);
    }
    std::wstring isDomainAuthenticatedByTlsString = !!isDomainAuthenticatedByTls ? L"true" : L"false";

    return Utility::PrintInstanceHeader(L"INetwork2 object") +
        wil::str_printf<std::wstring>(
            L"    IsDomainAuthenticatedBy(None): %ws\n"
            L"    IsDomainAuthenticatedBy(Ldap): %ws\n"
            L"    IsDomainAuthenticatedBy(Tls): %ws\n",
            ToStringCheckingErrors(isDomainAuthenticatedByNoneError, isDomainAuthenticatedByNoneString).c_str(),
            ToStringCheckingErrors(isDomainAuthenticatedByLdapError, isDomainAuthenticatedByLdapString).c_str(),
            ToStringCheckingErrors(isDomainAuthenticatedByTlsError, isDomainAuthenticatedByTlsString).c_str()) +
        Utility::PrintInstanceFooter();
}

std::wstring PublicNlm::Log(_In_ INetwork* pNetwork) const
{
    NLM_NETWORK_CATEGORY nlmCategory{NLM_NETWORK_CATEGORY_PUBLIC};
    THROW_IF_FAILED(pNetwork->GetCategory(&nlmCategory));

    NLM_CONNECTIVITY networkConnectivity{NLM_CONNECTIVITY_DISCONNECTED};
    THROW_IF_FAILED(pNetwork->GetConnectivity(&networkConnectivity));

    wil::unique_bstr description;
    THROW_IF_FAILED(pNetwork->GetDescription(&description));

    NLM_DOMAIN_TYPE networkDomainType{NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK};
    THROW_IF_FAILED(pNetwork->GetDomainType(&networkDomainType));

    wil::unique_bstr networkName;
    THROW_IF_FAILED(pNetwork->GetName(&networkName));

    GUID networkId{};
    THROW_IF_FAILED(pNetwork->GetNetworkId(&networkId));

    std::vector<GUID> subInterfaceGuids;
    ComPtr<IEnumNetworkConnections> enumNetworkConnections;
    THROW_IF_FAILED(pNetwork->GetNetworkConnections(enumNetworkConnections.GetAddressOf()));

    ComPtr<IPropertyBag> networkProperties;
    THROW_IF_FAILED(pNetwork->QueryInterface<IPropertyBag>(&networkProperties));

    wil::unique_variant variantDomainAuthenticationFailed;
    networkProperties->Read(NA_DomainAuthenticationFailed, variantDomainAuthenticationFailed.addressof(), nullptr);
    wil::unique_variant variantNetworkClass;
    networkProperties->Read(NA_NetworkClass, variantNetworkClass.addressof(), nullptr);
    wil::unique_variant variantNameSetByPolicy;
    networkProperties->Read(NA_NameSetByPolicy, variantNameSetByPolicy.addressof(), nullptr);
    wil::unique_variant variantIconSetByPolicy;
    networkProperties->Read(NA_IconSetByPolicy, variantIconSetByPolicy.addressof(), nullptr);
    wil::unique_variant variantDescriptionSetByPolicy;
    networkProperties->Read(NA_DescriptionSetByPolicy, variantDescriptionSetByPolicy.addressof(), nullptr);
    wil::unique_variant variantCategorySetByPolicy;
    networkProperties->Read(NA_CategorySetByPolicy, variantCategorySetByPolicy.addressof(), nullptr);
    wil::unique_variant variantNameReadOnly;
    networkProperties->Read(NA_NameReadOnly, variantNameReadOnly.addressof(), nullptr);
    wil::unique_variant variantIconReadOnly;
    networkProperties->Read(NA_IconReadOnly, variantIconReadOnly.addressof(), nullptr);
    wil::unique_variant variantDescriptionReadOnly;
    networkProperties->Read(NA_DescriptionReadOnly, variantDescriptionReadOnly.addressof(), nullptr);
    wil::unique_variant variantCategoryReadOnly;
    networkProperties->Read(NA_CategoryReadOnly, variantCategoryReadOnly.addressof(), nullptr);
    wil::unique_variant variantAllowMerge;
    networkProperties->Read(NA_AllowMerge, variantAllowMerge.addressof(), nullptr);
    wil::unique_variant variantInternetConnectivityV4;
    networkProperties->Read(NA_InternetConnectivityV4, variantInternetConnectivityV4.addressof(), nullptr);
    wil::unique_variant variantInternetConnectivityV6;
    networkProperties->Read(NA_InternetConnectivityV6, variantInternetConnectivityV6.addressof(), nullptr);

    for (auto hr = S_OK; hr == S_OK;)
    {
        ULONG subfetched{0};
        ComPtr<INetworkConnection> subNetworkConnection;
        THROW_IF_FAILED(
            hr = enumNetworkConnections->Next(1, subNetworkConnection.GetAddressOf(), &subfetched));
        if (hr == S_OK)
        {
            GUID subAdapterId;
            THROW_IF_FAILED(subNetworkConnection->GetAdapterId(&subAdapterId));
            subInterfaceGuids.push_back(subAdapterId);
        }
    }

    WCHAR* pNetworkId = nullptr;
    StringFromCLSID(networkId, &pNetworkId);

    std::wstring returnString(L"INetwork object");
    returnString += wil::str_printf<std::wstring>(
        L"    Description: %ws\n"
        L"    Network Name: %ws\n"
        L"    Network ID: %s\n"
        L"    NLM Network Category: %ws\n"
        L"    NLM Connectivity: %ws\n"
        L"    NLM Domain Type: %ws\n"
        L"    Number of enumerated connections: %u\n",
        description.get(),
        networkName.get(),
        pNetworkId,
        Utility::ToString(nlmCategory),
        Utility::ToString(networkConnectivity).c_str(),
        Utility::ToString(networkDomainType),
        static_cast<DWORD>(subInterfaceGuids.size()));

    for (const auto& subAdapterGuid : subInterfaceGuids)
    {
        WCHAR* pSubAdapterGuid = nullptr;
        StringFromCLSID(subAdapterGuid, &pSubAdapterGuid);
        returnString += wil::str_printf<std::wstring>(L"      %ws\n", pSubAdapterGuid);
    }

    returnString += wil::str_printf<std::wstring>(
        L"    Property Bag fields:\n"
        L"      NA_NetworkClass: %ws\n"
        L"      NA_NameSetByPolicy: %ws\n"
        L"      NA_IconSetByPolicy: %ws\n"
        L"      NA_DescriptionSetByPolicy: %ws\n"
        L"      NA_CategorySetByPolicy: %ws\n"
        L"      NA_NameReadOnly: %ws\n"
        L"      NA_IconReadOnly: %ws\n"
        L"      NA_DescriptionReadOnly: %ws\n"
        L"      NA_CategoryReadOnly: %ws\n"
        L"      NA_AllowMerge: %ws\n"
        L"      NA_InternetConnectivityV4: %ws\n"
        L"      NA_InternetConnectivityV6: %ws\n",
        Utility::ToString(static_cast<NLM_NETWORK_CLASS>(variantNetworkClass.ulVal)).c_str(),
        Utility::ToString(variantNameSetByPolicy.addressof()).c_str(),
        Utility::ToString(variantIconSetByPolicy.addressof()).c_str(),
        Utility::ToString(variantDescriptionSetByPolicy.addressof()).c_str(),
        Utility::ToString(variantCategorySetByPolicy.addressof()).c_str(),
        Utility::ToString(variantNameReadOnly.addressof()).c_str(),
        Utility::ToString(variantIconReadOnly.addressof()).c_str(),
        Utility::ToString(variantDescriptionReadOnly.addressof()).c_str(),
        Utility::ToString(variantCategoryReadOnly.addressof()).c_str(),
        Utility::ToString(variantAllowMerge.addressof()).c_str(),
        Utility::ToString(static_cast<NLM_INTERNET_CONNECTIVITY>(variantInternetConnectivityV4.ulVal)).c_str(),
        Utility::ToString(static_cast<NLM_INTERNET_CONNECTIVITY>(variantInternetConnectivityV6.ulVal)).c_str());

    std::wstring network2String;
    ComPtr<INetwork2> network2;
    const auto hr = pNetwork->QueryInterface(network2.GetAddressOf());
    if (FAILED(hr))
    {
        network2String = wil::str_printf<std::wstring>(L"  ! <INetwork::QueryInterface(INetwork2) failed (0x%x)>", hr);
    }

    if (network2)
    {
        network2String.push_back(L'\n');
        network2String.append(LogINetwork2(network2.Get()));
    }

    returnString += network2String;

    return returnString;
}

std::wstring PublicNlm::Log(_In_ INetworkConnectionCost* pConnectionCost) const
{
    DWORD cost{0};
    THROW_IF_FAILED(pConnectionCost->GetCost(&cost));

    NLM_DATAPLAN_STATUS status{};
    THROW_IF_FAILED(pConnectionCost->GetDataPlanStatus(&status));

    WCHAR* pInterfaceGuid = nullptr;
    StringFromCLSID(status.InterfaceGuid, &pInterfaceGuid);

    SYSTEMTIME st{};
    FileTimeToSystemTime(&status.NextBillingCycle, &st);
    std::wstring nextBillingCycle(wil::str_printf<std::wstring>(L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds));

    FileTimeToSystemTime(&status.UsageData.LastSyncTime, &st);
    std::wstring nextSyncTime(wil::str_printf<std::wstring>(L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds));

    return wil::str_printf<std::wstring>(
            L"    InterfaceGuid: %ws\n"
            L"    Cost: %ws\n"
            L"    DataLimit (MB): %ws\n"
            L"    InboundBandwidth (Kbps): %ws\n"
            L"    OutboundBandwidth (Kbps): %ws\n"
            L"    MaxTransferSize (MB): %ws\n"
            L"    NextBillingCycle: %ws\n"
            L"    UsageData LastSyncTime: %ws\n"
            L"    UsageData Usage (MB): %ws\n",
            pInterfaceGuid,
            Utility::ToString(static_cast<NLM_CONNECTION_COST>(cost)).c_str(),
            status.DataLimitInMegabytes == DWORD_MAX ? L"-1" : std::to_wstring(status.DataLimitInMegabytes).c_str(),
            status.InboundBandwidthInKbps == DWORD_MAX ? L"-1" : std::to_wstring(status.InboundBandwidthInKbps).c_str(),
            status.OutboundBandwidthInKbps == DWORD_MAX ? L"-1" : std::to_wstring(status.OutboundBandwidthInKbps).c_str(),
            status.MaxTransferSizeInMegabytes == DWORD_MAX ? L"-1" : std::to_wstring(status.MaxTransferSizeInMegabytes).c_str(),
            nextBillingCycle.c_str(),
            nextSyncTime.c_str(),
            status.UsageData.UsageInMegabytes == DWORD_MAX ? L"-1" : std::to_wstring(status.UsageData.UsageInMegabytes).c_str());
}

std::wstring PublicNlm::Log(_In_ INetworkCostManager* pCostManager) const
{
    DWORD cost{0};
    THROW_IF_FAILED(pCostManager->GetCost(&cost, nullptr));
    const auto nlmConnectionCost = static_cast<NLM_CONNECTION_COST>(cost);

    NLM_DATAPLAN_STATUS status{};
    THROW_IF_FAILED(pCostManager->GetDataPlanStatus(&status, nullptr));

    WCHAR* pInterfaceGuid = nullptr;
    StringFromCLSID(status.InterfaceGuid, &pInterfaceGuid);

    SYSTEMTIME st{};
    FileTimeToSystemTime(&status.NextBillingCycle, &st);
    std::wstring nextBillingCycle(wil::str_printf<std::wstring>(L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds));

    FileTimeToSystemTime(&status.UsageData.LastSyncTime, &st);
    std::wstring nextSyncTime(wil::str_printf<std::wstring>(L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds));

    return wil::str_printf<std::wstring>(
        L"    InterfaceGuid: %ws\n"
        L"    Cost: %ws\n"
        L"    DataLimit (MB): %ws\n"
        L"    InboundBandwidth (Kbps): %ws\n"
        L"    OutboundBandwidth (Kbps): %ws\n"
        L"    MaxTransferSize (MB): %ws\n"
        L"    NextBillingCycle: %ws\n"
        L"    UsageData LastSyncTime: %ws\n"
        L"    UsageData Usage (MB): %ws\n",
        pInterfaceGuid,
        Utility::ToString(nlmConnectionCost).c_str(),
        status.DataLimitInMegabytes == DWORD_MAX ? L"-1" : std::to_wstring(status.DataLimitInMegabytes).c_str(),
        status.InboundBandwidthInKbps == DWORD_MAX ? L"-1" : std::to_wstring(status.InboundBandwidthInKbps).c_str(),
        status.OutboundBandwidthInKbps == DWORD_MAX ? L"-1" : std::to_wstring(status.OutboundBandwidthInKbps).c_str(),
        status.MaxTransferSizeInMegabytes == DWORD_MAX ? L"-1" : std::to_wstring(status.MaxTransferSizeInMegabytes).c_str(),
        nextBillingCycle.c_str(),
        nextSyncTime.c_str(),
        status.UsageData.UsageInMegabytes == DWORD_MAX ? L"-1" : std::to_wstring(status.UsageData.UsageInMegabytes).c_str());
}
