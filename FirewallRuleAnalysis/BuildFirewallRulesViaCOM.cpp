#include <string>

#include <Windows.h>
#include <netfw.h>
#include <sddl.h>

#include <wil/com.h>
#include <wil/resource.h>

#include "FirewallRuleBuilder.h"


namespace details
{
    std::tuple<DWORD, std::wstring> ConvertSidStringToUserName(_In_ PCWSTR localUserOwner)
    {
        DWORD errorRetrievingOwnerUsername{};
        std::wstring ruleOwnerUsername{};

        wil::unique_any_psid convertedSid;
        if (ConvertStringSidToSidW(localUserOwner, &convertedSid))
        {
            DWORD nameLength{};
            DWORD referencedDomainNameLength{};
            SID_NAME_USE sidNameUse{};
            LookupAccountSidW(
                nullptr, // lookup on the local system
                convertedSid.get(),
                nullptr,
                &nameLength,
                nullptr,
                &referencedDomainNameLength,
                &sidNameUse);
            if (nameLength == 0)
            {
                errorRetrievingOwnerUsername = GetLastError();
            }
            else
            {
                // remove the embedded null-terminator
                ruleOwnerUsername.resize(nameLength);

                std::wstring referencedDomainNameString;
                if (referencedDomainNameLength > 0)
                {
                    referencedDomainNameString.resize(referencedDomainNameLength);
                }

                if (!LookupAccountSidW(
                    nullptr, // lookup on the local system
                    convertedSid.get(),
                    ruleOwnerUsername.data(),
                    &nameLength,
                    referencedDomainNameLength > 0 ? referencedDomainNameString.data() : nullptr,
                    &referencedDomainNameLength,
                    &sidNameUse))
                {
                    errorRetrievingOwnerUsername = GetLastError();
                }
                else
                {
                    // remove the embedded null-terminator
                    ruleOwnerUsername.resize(ruleOwnerUsername.size() - 1);
                    if (referencedDomainNameLength > 0)
                    {
                        referencedDomainNameString.resize(referencedDomainNameString.size() - 1);
                    }

                    if (!referencedDomainNameString.empty())
                    {
                        std::wstring fullOwnerName{std::move(referencedDomainNameString)};
                        fullOwnerName.append(L"\\");
                        fullOwnerName.append(ruleOwnerUsername);
                        ruleOwnerUsername = std::move(fullOwnerName);
                    }
                }
            }
        }

        return {errorRetrievingOwnerUsername, ruleOwnerUsername};
    }
}

NormalizedFirewallRule BuildFirewallRuleInfo(const wil::com_ptr<INetFwRule3>& rule) noexcept
{
    NormalizedFirewallRule ruleInfo{};
    // save for later if we determine to delete the rule (if it's a duplicate)
    // also avoids the cost of deleting each rule object as we enumerate all rules
    // (deleting the rule object requires a COM call back to the firewall service)
    ruleInfo.rule = rule;

    try
    {
        // name and description are volatile - they don't impact the final filter
        THROW_IF_FAILED(rule->get_Name(&ruleInfo.ruleName));
        THROW_IF_FAILED(rule->get_Description(&ruleInfo.ruleDescription));

        wil::unique_bstr applicationName{};
        THROW_IF_FAILED(rule->get_ApplicationName(&applicationName));
        ruleInfo.AppendValue(applicationName.get());

        wil::unique_bstr serviceName{};
        THROW_IF_FAILED(rule->get_ServiceName(&serviceName));
        ruleInfo.AppendValue(serviceName.get());

        LONG protocol{};
        THROW_IF_FAILED(rule->get_Protocol(&protocol));
        ruleInfo.AppendValue(protocol);

        wil::unique_bstr localPorts{};
        THROW_IF_FAILED(rule->get_LocalPorts(&localPorts));
        ruleInfo.AppendValue(localPorts.get());

        wil::unique_bstr remotePorts{};
        THROW_IF_FAILED(rule->get_RemotePorts(&remotePorts));
        ruleInfo.AppendValue(remotePorts.get());

        wil::unique_bstr localAddresses{};
        THROW_IF_FAILED(rule->get_LocalAddresses(&localAddresses));
        ruleInfo.AppendValue(localAddresses.get());

        wil::unique_bstr remoteAddresses{};
        THROW_IF_FAILED(rule->get_RemoteAddresses(&remoteAddresses));
        ruleInfo.AppendValue(remoteAddresses.get());

        wil::unique_bstr icmpTypesAndCodes{};
        THROW_IF_FAILED(rule->get_IcmpTypesAndCodes(&icmpTypesAndCodes));
        ruleInfo.AppendValue(icmpTypesAndCodes.get());

        NET_FW_RULE_DIRECTION direction{};
        THROW_IF_FAILED(rule->get_Direction(&direction));
        ruleInfo.AppendValue(direction);
        ruleInfo.ruleDirection = direction;

        wil::unique_variant interfaces;
        THROW_IF_FAILED(rule->get_Interfaces(&interfaces));
        ruleInfo.AppendValue(interfaces);

        wil::unique_bstr interfaceTypes;
        THROW_IF_FAILED(rule->get_InterfaceTypes(&interfaceTypes));
        ruleInfo.AppendValue(interfaceTypes.get());

        VARIANT_BOOL enabled{};
        THROW_IF_FAILED(rule->get_Enabled(&enabled));
        // not going to require matching enabled vs disabled when matching the rules
        // ruleInfo.AppendValue(enabled);
        ruleInfo.ruleEnabled = !!enabled;

        // if there are 2 rules with the same names, but different groups
        // then we want to keep them both - since presumably that have different sources
        // and thus should not be considered duplicates
        wil::unique_bstr grouping{};
        THROW_IF_FAILED(rule->get_Grouping(&grouping));
        ruleInfo.AppendValue(grouping.get());
        ruleInfo.ruleGrouping = std::move(grouping);

        LONG profiles{};
        THROW_IF_FAILED(rule->get_Profiles(&profiles));
        ruleInfo.AppendValue(profiles);
        ruleInfo.ruleProfiles = profiles;

        VARIANT_BOOL edgeTraversal{};
        THROW_IF_FAILED(rule->get_EdgeTraversal(&edgeTraversal));
        ruleInfo.AppendValue(edgeTraversal);

        NET_FW_ACTION action{};
        THROW_IF_FAILED(rule->get_Action(&action));
        ruleInfo.AppendValue(action);
        ruleInfo.ruleAction = action;

        LONG edgeTraversalOptions{};
        THROW_IF_FAILED(rule->get_EdgeTraversalOptions(&edgeTraversalOptions));
        ruleInfo.AppendValue(edgeTraversalOptions);

        wil::unique_bstr localAppPackageId{};
        THROW_IF_FAILED(rule->get_LocalAppPackageId(&localAppPackageId));
        ruleInfo.AppendValue(localAppPackageId.get());

        wil::unique_bstr localUserOwner{};
        THROW_IF_FAILED(rule->get_LocalUserOwner(&localUserOwner));
        ruleInfo.AppendValue(localUserOwner.get());

        if (localUserOwner)
        {
            const auto userConversion = details::ConvertSidStringToUserName(localUserOwner.get());
            ruleInfo.errorRetrievingOwnerUsername = std::get<0>(userConversion);
            ruleInfo.ruleOwnerUsername = std::get<1>(userConversion);
            /*
            if (ruleInfo.errorRetrievingOwnerUsername != NO_ERROR)
            {
                wprintf(L"[rule %ws] (%ws) failed with error 0x%x\n",
                    ruleInfo.ruleName.get(),
                    localUserOwner.get(),
                    ruleInfo.errorRetrievingOwnerUsername);
            }
            else
            {
                wprintf(L"[rule %ws] (%ws) successfully resolved to %ws\n",
                    ruleInfo.ruleName.get(),
                    localUserOwner.get(),
                    ruleInfo.ruleOwnerUsername.c_str());
            }
            */
        }

        wil::unique_bstr localUserAuthorizedList{};
        THROW_IF_FAILED(rule->get_LocalUserAuthorizedList(&localUserAuthorizedList));
        ruleInfo.AppendValue(localUserAuthorizedList.get());

        wil::unique_bstr remoteUserAuthorizedList{};
        THROW_IF_FAILED(rule->get_RemoteUserAuthorizedList(&remoteUserAuthorizedList));
        ruleInfo.AppendValue(remoteUserAuthorizedList.get());

        wil::unique_bstr remoteMachineAuthorizedList{};
        THROW_IF_FAILED(rule->get_RemoteMachineAuthorizedList(&remoteMachineAuthorizedList));
        ruleInfo.AppendValue(remoteMachineAuthorizedList.get());

        LONG secureFlags{};
        THROW_IF_FAILED(rule->get_SecureFlags(&secureFlags));
        ruleInfo.AppendValue(secureFlags);
    }
    catch (...)
    {
        wprintf(L"Failed to read rule %ws (%ws) - 0x%x\n",
                ruleInfo.ruleName ? ruleInfo.ruleName.get() : L"(unknown)",
                ruleInfo.ruleDescription ? ruleInfo.ruleDescription.get() : L"(unknown)",
                wil::ResultFromCaughtException());
        return {};
    }

    return ruleInfo;
}
