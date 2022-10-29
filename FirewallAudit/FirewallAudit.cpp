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

    void SetAllowFile(wil::unique_hfile&& allowHFile)
    {
        m_allowFile = std::move(allowHFile);
        // always write the header first into the csv
        WriteNextLine(m_allowFile, PrintFileHeader(), false);
    }

    void SetDropFile(wil::unique_hfile&& dropHFile)
    {
        m_dropFile = std::move(dropHFile);
        WriteNextLine(m_dropFile, PrintFileHeader(), false);
    }

    void SetFailureFile(wil::unique_hfile&& failureHFile)
    {
        m_failureFile = std::move(failureHFile);
        WriteNextLine(m_failureFile, PrintFileHeader(), false);
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
    wil::unique_hfile m_allowFile;
    wil::unique_hfile m_dropFile;
    wil::unique_hfile m_failureFile;

    static void WriteNextLine(const wil::unique_hfile& fileHandle, std::string&& text, bool printConsoleStatus = true) noexcept
    try
    {
        // guarantee carriage-return + line-feed is at the end of each line written
        constexpr auto* endOfLine{"\r\n"};
        text.append(endOfLine);

        const auto writeResult = WriteFile(fileHandle.get(), text.data(), static_cast<DWORD>(text.size()), nullptr, nullptr);
        if (printConsoleStatus)
        {
            if (!writeResult)
            {
                const auto gle = GetLastError();
                printf("WriteFile failed :  %lu\n", gle);
            }
            else
            {
                printf("%hs\n", text.c_str());
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

wil::unique_hfile CreateCsvFile(_In_ PCWSTR filename)
{
    wil::unique_hfile fileHandle{::CreateFileW(
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
    fwprintf(stdout, L"Invalid arguments\n"
        "FirewallAudit.exe <FAILURE | DROP | ALLOW>:<output_filename>\n"
        " e.g. FirewallAudit.exe drop:drop.csv\n"
        " note: csv will be appended as the file extension to the filename specified\n"
        "\nThe specified file will be overwritten\n");
}

bool ParseFileType(OutputFileContext& outputFileContext, _In_ PCWSTR inputString)
{
    constexpr auto ignoreCase = TRUE;
    if (CompareStringOrdinal(L"failure:", 8, inputString, 8, ignoreCase) == CSTR_EQUAL)
    {
        const auto* fileName = inputString + 8;
        if (wcslen(fileName) == 0)
        {
            return false;
        }

        outputFileContext.SetFailureFile(CreateCsvFile(fileName));
        return true;
    }

    if (CompareStringOrdinal(L"drop:", 5, inputString, 5, ignoreCase) == CSTR_EQUAL)
    {
        const auto* fileName = inputString + 5;
        if (wcslen(fileName) == 0)
        {
            return false;
        }

        outputFileContext.SetDropFile(CreateCsvFile(fileName));
        return true;
    }

    if (CompareStringOrdinal(L"allow:", 6, inputString, 6, ignoreCase) == CSTR_EQUAL)
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

// arguments: <failure:filename.csv> <drop:filename.csv> <allow:filename.cvs>
int __cdecl wmain(int argc, wchar_t** argv)
try
{
    if ((argc < 2) || (argc > 4))
    {
        PrintHelp();
        return ERROR_INVALID_PARAMETER;
    }

    OutputFileContext outputFileContext;
    for (auto i = 1; i < argc; ++i)
    {
        if (!ParseFileType(outputFileContext, argv[i]))
        {
            PrintHelp();
            return ERROR_INVALID_PARAMETER;
        }
    }

    WSADATA wsadata;
    THROW_IF_WIN32_ERROR(WSAStartup(WINSOCK_VERSION, &wsadata));

    static wil::slim_event_manual_reset exitEvent{};
    THROW_IF_WIN32_BOOL_FALSE(SetConsoleCtrlHandler(
        [](DWORD) -> BOOL { exitEvent.SetEvent(); return TRUE; },
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
    // passing 
    THROW_IF_WIN32_ERROR(FwpmNetEventSubscribe4(engineHandle, &subscription, FirewallNetEventCallback, &outputFileContext, &eventsHandle));

    fwprintf(stdout, L"\nProcessing Firewall events - hit ctrl-c to exit\n");
    exitEvent.wait();

    // upon exit, all d'tors will execute in reverse order (correctly):
    // - guarantees all FW subscriptions have stopped
    // - then closes the FW handle
    // - then waits for all pended IO to complete within the OutputFileContext
    // - then closes the output file handle
}
catch (...)
{
    fwprintf(stderr, L"\nError - 0x%x\n", wil::ResultFromCaughtException());
}
