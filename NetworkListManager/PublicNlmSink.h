// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <algorithm>
#include <iostream>
#include <string>
#include <WinSock2.h>
#include <windows.h>
#include <wrl.h>
#include <wil/resource.h>
#include <wil/stl.h>
#include <netlistmgr.h>
#include "Utility.h"

class PublicNLMSink final
    : public Microsoft::WRL::RuntimeClass<Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, INetworkEvents, INetworkConnectionEvents, INetworkConnectionCostEvents, INetworkCostManagerEvents, INetworkListManagerEvents>
{

public:
    PublicNLMSink() = default;
    ~PublicNLMSink() override = default;

    PublicNLMSink(const PublicNLMSink&) = delete;
    PublicNLMSink& operator=(const PublicNLMSink&) = delete;
    PublicNLMSink(PublicNLMSink&&) = delete;
    PublicNLMSink& operator=(PublicNLMSink&&) = delete;

    IFACEMETHODIMP NetworkAdded(GUID networkId) noexcept override;
    IFACEMETHODIMP NetworkDeleted(GUID networkId) noexcept override;
    IFACEMETHODIMP NetworkConnectivityChanged(GUID networkId, NLM_CONNECTIVITY connectivity) noexcept override;
    IFACEMETHODIMP NetworkPropertyChanged(GUID networkId, NLM_NETWORK_PROPERTY_CHANGE property) noexcept override;
    IFACEMETHODIMP NetworkConnectionConnectivityChanged(GUID connectionId, NLM_CONNECTIVITY connectivity) noexcept override;
    IFACEMETHODIMP NetworkConnectionPropertyChanged(GUID connectionId, NLM_CONNECTION_PROPERTY_CHANGE property) noexcept override;
    IFACEMETHODIMP ConnectionCostChanged(GUID connectionId, DWORD cost) noexcept override;
    IFACEMETHODIMP ConnectionDataPlanStatusChanged(GUID connectionId) noexcept override;
    IFACEMETHODIMP ConnectivityChanged(NLM_CONNECTIVITY connectivity) noexcept override;
    IFACEMETHODIMP CostChanged(DWORD cost, __RPC__in_opt NLM_SOCKADDR* pDestAddr) noexcept override;
    IFACEMETHODIMP DataPlanStatusChanged(__RPC__in_opt NLM_SOCKADDR* pDestAddr) noexcept override;
};
