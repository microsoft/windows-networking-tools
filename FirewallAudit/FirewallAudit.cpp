// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdio>
#include <memory>
#include <string>
#include <type_traits>
#include "platform_headers.h"
#include "PrintFirewallAuditEvents.h"


class OutputFileContext
{
public:
    OutputFileContext() = default;
    ~OutputFileContext() noexcept = default;

    void EnableConsoleOutput() noexcept
    {
        m_writeToConsole = true;
        WriteNextLine(wil::shared_hfile{}, PrintFileHeader(), true);
    }

    void SetAllowFile(wil::shared_hfile allowHFile)
    {
        THROW_HR_IF(E_INVALIDARG, m_allowFile.is_valid());
        m_allowFile = std::move(allowHFile);
        // always write the header first into the csv
        WriteNextLine(m_allowFile, PrintFileHeader(), true);
    }

    void SetDropFile(wil::shared_hfile dropHFile)
    {
        THROW_HR_IF(E_INVALIDARG, m_dropFile.is_valid());
        m_dropFile = std::move(dropHFile);
        WriteNextLine(m_dropFile, PrintFileHeader(), true);
    }

    void SetFailureFile(wil::shared_hfile failureHFile)
    {
        THROW_HR_IF(E_INVALIDARG, m_failureFile.is_valid());
        m_failureFile = std::move(failureHFile);
        WriteNextLine(m_failureFile, PrintFileHeader(), true);
    }

    void SetAllEventsFile(const wil::shared_hfile& allEventsHFile)
    {
        THROW_HR_IF(E_INVALIDARG, m_allowFile.is_valid());
        m_allowFile = allEventsHFile;

        THROW_HR_IF(E_INVALIDARG, m_dropFile.is_valid());
        m_dropFile = allEventsHFile;

        THROW_HR_IF(E_INVALIDARG, m_failureFile.is_valid());
        m_failureFile = allEventsHFile;
        
        WriteNextLine(m_failureFile, PrintFileHeader(), true);
    }

    [[nodiscard]] bool AllowEnabled() const noexcept
    {
        return static_cast<bool>(m_allowFile);
    }

    [[nodiscard]] bool DropEnabled() const noexcept
    {
        return static_cast<bool>(m_dropFile);
    }

    [[nodiscard]] bool FailureEnabled() const noexcept
    {
        return static_cast<bool>(m_failureFile);
    }

    void WriteAllow(std::string&& text) const noexcept
    try
    {
        WriteNextLine(m_allowFile, std::move(text));
    }
    CATCH_LOG()

    void WriteDrop(std::string&& text) const noexcept
    try
    {
        WriteNextLine(m_dropFile, std::move(text));
    }
    CATCH_LOG()

    void WriteFailure(std::string&& text) const noexcept
    try
    {
        WriteNextLine(m_failureFile, std::move(text));
    }
    CATCH_LOG()

    OutputFileContext(const OutputFileContext&) = delete;
    OutputFileContext& operator=(const OutputFileContext&) = delete;
    OutputFileContext(OutputFileContext&&) = delete;
    OutputFileContext& operator=(OutputFileContext&&) = delete;

private:
    // must be declared in this order
    // the c'tor must initialize threadpoolIocp with the hFile
    // the d'tor must first teardown threadpoolIocp, then hFile
    wil::shared_hfile m_allowFile;
    wil::shared_hfile m_dropFile;
    wil::shared_hfile m_failureFile;
    bool m_writeToConsole{false};
    mutable bool m_headerWrittenToConsole{false};

    void WriteNextLine(const wil::shared_hfile& fileHandle, std::string&& text, bool printingHeader = false) const noexcept
    try
    {
        if (m_writeToConsole && (!printingHeader || (printingHeader && !m_headerWrittenToConsole)))
        {
            fwprintf(stdout, L"%hs\n", text.c_str());
            if (printingHeader)
            {
                m_headerWrittenToConsole = true;
            }
        }

        if (fileHandle)
        {
            // guarantee carriage-return + line-feed is at the end of each line written
            constexpr auto* endOfLine{"\r\n"};
            text.append(endOfLine);

            const auto writeResult = WriteFile(fileHandle.get(), text.data(), static_cast<DWORD>(text.size()), nullptr, nullptr);
            if (!writeResult)
            {
                const auto gle = GetLastError();
                fwprintf(stderr, L"WriteFile failed :  %lu\n", gle);
            }
        }
    }
    CATCH_LOG()
};

void CALLBACK FirewallNetEventCallback(void* context, const FWPM_NET_EVENT5* event) noexcept
try
{
    const auto* outputFileContext = static_cast<OutputFileContext*>(context);
    switch (event->type)
    {
        case FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE:
        {
            if (outputFileContext->FailureEnabled())
            {
                outputFileContext->WriteFailure(PrintFirewallAuditEvent(event->header, event->ikeMmFailure));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE:
        {
            if (outputFileContext->FailureEnabled())
            {
                outputFileContext->WriteFailure(PrintFirewallAuditEvent(event->header, event->ikeQmFailure));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE:
        {
            if (outputFileContext->FailureEnabled())
            {
                outputFileContext->WriteFailure(PrintFirewallAuditEvent(event->header, event->ikeEmFailure));
            }
            break;
        }

        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
        {
            if (outputFileContext->DropEnabled())
            {
                outputFileContext->WriteDrop(PrintFirewallAuditEvent(event->header, event->classifyDrop));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
        {
            if (outputFileContext->DropEnabled())
            {
                outputFileContext->WriteDrop(PrintFirewallAuditEvent(event->header, event->ipsecDrop));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP:
        {
            if (outputFileContext->DropEnabled())
            {
                outputFileContext->WriteDrop(PrintFirewallAuditEvent(event->header, event->idpDrop));
            }
            break;
        }

        case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
        {
            if (outputFileContext->DropEnabled())
            {
                outputFileContext->WriteDrop(PrintFirewallAuditEvent(event->header, event->capabilityDrop));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
        {
            if (outputFileContext->DropEnabled())
            {
                outputFileContext->WriteDrop(PrintFirewallAuditEvent(event->header, event->classifyDropMac));
            }
            break;
        }

        case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
        {
            if (outputFileContext->AllowEnabled())
            {
                outputFileContext->WriteAllow(PrintFirewallAuditEvent(event->header, event->classifyAllow));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
        {
            if (outputFileContext->AllowEnabled())
            {
                outputFileContext->WriteAllow(PrintFirewallAuditEvent(event->header, event->capabilityAllow));
            }
            break;
        }
        case FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL:
        {
            if (outputFileContext->AllowEnabled())
            {
                outputFileContext->WriteAllow(PrintFirewallAuditEvent(event->header, event->lpmPacketArrival));
            }
            break;
        }
        default:
            DebugBreak();
    }
}
CATCH_LOG()

wil::shared_hfile CreateCsvFile(_In_ PCWSTR filename)
{
    wil::shared_hfile fileHandle{CreateFileW(
        filename,
        GENERIC_WRITE,
        FILE_SHARE_READ, // allow others to read the file while we write to it
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr)};
    THROW_LAST_ERROR_IF_NULL(fileHandle.get());
    return fileHandle;
}

void PrintHelp() noexcept
{
    fwprintf(stdout,
        L"\nFirewallAudit.exe [all:<all_filename.csv>] | [<failure:failure_filename.csv> <drop:drop_filename.csv> allow:<allow_filename.csv>] | [console]\n"
        L" e.g. FirewallAudit.exe all:all.csv\n"
        L" e.g. FirewallAudit.exe failure:failure.csv drop:drop.csv allow:allow.csv\n"
        L" Append console to the commandline to also write out events to the current console\n"
        L"\nThe specified file will be overwritten\n");
}

bool ParseForTheConsoleArgument(OutputFileContext& outputFileContext, _In_ PCWSTR inputString)
{
    constexpr auto ignoreCase = TRUE;
    constexpr auto* allArgument = L"console";
    if (CompareStringOrdinal(allArgument, 7, inputString, 7, ignoreCase) != CSTR_EQUAL)
    {
        return false;
    }

    outputFileContext.EnableConsoleOutput();
    return true;
}

bool ParseForTheAllArgument(OutputFileContext& outputFileContext, _In_ PCWSTR inputString)
{
    constexpr auto ignoreCase = TRUE;
    constexpr auto* allArgument = L"all:";
    if (CompareStringOrdinal(allArgument, 4, inputString, 4, ignoreCase) == CSTR_EQUAL)
    {
        const auto* fileName = inputString + 4;
        if (wcslen(fileName) == 0)
        {
            return false;
        }

        outputFileContext.SetAllEventsFile(CreateCsvFile(fileName));
        return true;
    }

    return false;
}

bool ParseIndividualFileTypes(OutputFileContext& outputFileContext, _In_ PCWSTR inputString)
{
    constexpr auto ignoreCase = TRUE;

    constexpr auto* failureArgument = L"failure:";
    if (CompareStringOrdinal(failureArgument, 8, inputString, 8, ignoreCase) == CSTR_EQUAL)
    {
        const auto* fileName = inputString + 8;
        if (wcslen(fileName) == 0)
        {
            return false;
        }

        outputFileContext.SetFailureFile(CreateCsvFile(fileName));
        return true;
    }

    constexpr auto* dropArgument = L"drop:";
    if (CompareStringOrdinal(dropArgument, 5, inputString, 5, ignoreCase) == CSTR_EQUAL)
    {
        const auto* fileName = inputString + 5;
        if (wcslen(fileName) == 0)
        {
            return false;
        }

        outputFileContext.SetDropFile(CreateCsvFile(fileName));
        return true;
    }

    constexpr auto* allowArgument = L"allow:";
    if (CompareStringOrdinal(allowArgument, 6, inputString, 6, ignoreCase) == CSTR_EQUAL)
    {
        const auto* fileName = inputString + 6;
        if (wcslen(fileName) == 0)
        {
            return false;
        }

        outputFileContext.SetAllowFile(CreateCsvFile(fileName));
        return true;
    }

    return false;
}

// arguments: allevents<failure:filename.csv> <drop:filename.csv> <allow:filename.cvs>
int __cdecl wmain(int argc, wchar_t** argv)
try
{
    if ((argc < 2) || (argc > 5))
    {
        PrintHelp();
        return ERROR_INVALID_PARAMETER;
    }

    std::vector<std::wstring> outputParameters;
    for (auto i = 1; i < argc; ++i)
    {
        outputParameters.emplace_back(argv[i]);
    }

    OutputFileContext outputFileContext;

    for (auto iter = outputParameters.begin(); iter != outputParameters.end(); ++iter)
    {
        if (ParseForTheConsoleArgument(outputFileContext, iter->c_str()))
        {
            outputParameters.erase(iter);
            break;
        }
    }

    // check see if they want all:
    auto parseForIndividualFiles = true;
    for (auto iter = outputParameters.begin(); iter != outputParameters.end(); ++iter)
    {
        if (ParseForTheAllArgument(outputFileContext, iter->c_str()))
        {
            parseForIndividualFiles = false;
            outputParameters.erase(iter);
            break;
        }
    }

    // else look for each individual option
    if (parseForIndividualFiles)
    {
        auto iter = outputParameters.begin();
        while (iter != outputParameters.end())
        {
            if (!ParseIndividualFileTypes(outputFileContext, iter->c_str()))
            {
                PrintHelp();
                return ERROR_INVALID_PARAMETER;
            }

            outputParameters.erase(iter);
            iter = outputParameters.begin();
        }
    }

    THROW_HR_IF(E_INVALIDARG, !outputParameters.empty());

    WSADATA wsadata;
    THROW_IF_WIN32_ERROR(WSAStartup(WINSOCK_VERSION, &wsadata));

    static wil::slim_event_manual_reset exitEvent{};
    THROW_IF_WIN32_BOOL_FALSE(SetConsoleCtrlHandler(
        [] (DWORD) -> BOOL { exitEvent.SetEvent(); return TRUE; },
        TRUE));

    GUID firewallAuditSession{};
    THROW_IF_WIN32_ERROR(UuidCreate(&firewallAuditSession));

    HANDLE engineHandle{nullptr};
    const auto closeFwHandleOnExit = wil::scope_exit([&] {
        if (engineHandle)
        {
            LOG_IF_WIN32_ERROR(FwpmEngineClose0(engineHandle));
        }
    });
    THROW_IF_WIN32_ERROR(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engineHandle));

    FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
    subscription.sessionKey = firewallAuditSession;

    HANDLE eventsHandle{nullptr};
    const auto unregisterOnExit = wil::scope_exit([&] {
        if (eventsHandle)
        {
            LOG_IF_WIN32_ERROR(FwpmNetEventUnsubscribe0(engineHandle, eventsHandle));
        }
    });

    fwprintf(stdout, L"\n");
    THROW_IF_WIN32_ERROR(FwpmNetEventSubscribe4(engineHandle, &subscription, FirewallNetEventCallback, &outputFileContext, &eventsHandle));

    exitEvent.wait();

    // upon exit, all d'tors will execute in reverse order (correctly):
    // - guarantees all FW subscriptions have stopped
    // - then closes the FW handle
    // - then waits for all pended IO to complete within the OutputFileContext
    // - then closes the output file handle
    return ERROR_SUCCESS;
}
catch (...)
{
    const auto hr = wil::ResultFromCaughtException();
    fwprintf(stderr, L"\nError - 0x%x\n\n", hr);
    PrintHelp();
    return hr;
}
