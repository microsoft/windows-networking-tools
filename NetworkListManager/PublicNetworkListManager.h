// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>
#include <WinSock2.h>
#include <windows.h>
#include <wrl.h>
#include <netlistmgr.h>
#include "PublicNlmSink.h"
#include "Utility.h"

using unique_connectionpoint_token = wil::unique_com_token<IConnectionPoint, DWORD, decltype(&IConnectionPoint::Unadvise), &IConnectionPoint::Unadvise>;

class PublicNlm
{
public:
    PublicNlm();
    ~PublicNlm() = default;
    PublicNlm(const PublicNlm&) = delete;
    PublicNlm& operator=(const PublicNlm&) = delete;
    PublicNlm(PublicNlm&&) = delete;
    PublicNlm& operator=(PublicNlm&&) = delete;

    void TryStartEventNotifications();

    [[nodiscard]] std::wstring GetConnectivity() const;
    [[nodiscard]] std::wstring GetNetworkCost() const;
    [[nodiscard]] std::wstring GetNetworkConnectionCost() const;
    [[nodiscard]] std::wstring GetNetworkConnections() const;
    [[nodiscard]] std::wstring GetNetworks(NLM_ENUM_NETWORK networkEnum) const;

private:
    class AdviseHandler
    {
    public:
        AdviseHandler() = default;
        ~AdviseHandler() = default;

        AdviseHandler(const AdviseHandler&) = delete;
        AdviseHandler& operator=(const AdviseHandler&) = delete;
        AdviseHandler(AdviseHandler&&) = delete;
        AdviseHandler& operator=(AdviseHandler&&) = delete;

        // typename T is the connection point interface which is implemented
        // typename C is the server object implementing IConnectionPoint to Advise()
        // typename S is the client's sink object (must implement type T)
        template <typename T, typename C, typename S>
        void AdviseInProcObject(_In_ Microsoft::WRL::ComPtr<C> sourceObject, _In_ S* connectionSink)
        {
            Microsoft::WRL::ComPtr<IConnectionPointContainer> pointContainer;
            Microsoft::WRL::ComPtr<IConnectionPoint> connectionPoint;
            
            THROW_IF_FAILED(sourceObject.As<IConnectionPointContainer>(&pointContainer));

            THROW_IF_FAILED(pointContainer->FindConnectionPoint(__uuidof(T), connectionPoint.GetAddressOf()));

            unique_connectionpoint_token newInstance{connectionPoint.Get()};
            THROW_IF_FAILED(connectionPoint->Advise(connectionSink, &newInstance));
            adviseInstances.emplace_back(std::move(newInstance));
        }

        void Reset() noexcept
        {
            adviseInstances.clear();
        }

    private:
        std::vector<unique_connectionpoint_token> adviseInstances;
    };

    std::wstring Log(_In_ INetworkConnection* networkConnection) const;
    std::wstring Log(_In_ INetwork* network) const;
    std::wstring Log(_In_ INetworkConnectionCost* connectionCost) const;
    std::wstring Log(_In_ INetworkCostManager* costManager) const;

    Microsoft::WRL::ComPtr<INetworkListManager> m_netListManager;
    Microsoft::WRL::ComPtr<IEnumNetworkConnections> m_enumNetworkConnections;
    Microsoft::WRL::ComPtr<IEnumNetworks> m_enumNetworks;

    // the sink to process all notifications
    wil::critical_section m_sinkLock{500};
    Microsoft::WRL::ComPtr<INetworkConnectionEvents> m_connectionSink;
    AdviseHandler m_publicNlmEvents;
};
