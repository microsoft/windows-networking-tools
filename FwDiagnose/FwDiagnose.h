// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <string>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <vector>
#include <cstdint>

#include <Windows.h>
#include <Objbase.h>
#include <icftypes.h>
#include <wil/result_macros.h>

bool
DebugOutputEnabled() noexcept;
bool
VerboseOutputEnabled() noexcept;
bool
AnalyzeRulesEnabled() noexcept;
bool
CleanBrokenRulesEnabled() noexcept;

std::vector<NET_FW_PROFILE_TYPE2>
GetShieldsUpProfiles() noexcept;
bool
TurnOffShieldsUpSet() noexcept;
bool
TurnOnShieldsUpSet() noexcept;

bool
WfpOutputEnabled() noexcept;
bool
WfpEventEnumerationEnabled() noexcept;
bool
RemoveWfpCalloutFiltersEnabled() noexcept;

const std::wstring&
RemoveCalloutDriverName() noexcept;
PCWSTR
GetNamedEventForRestoringFilters() noexcept;

// Records a failure that was reported but did not stop the run. The first one recorded becomes the process exit code.
void
RecordOperationFailure(HRESULT error) noexcept;
HRESULT
FirstOperationFailure() noexcept;

inline std::wstring
GuidToString(const GUID& guid)
{
	wchar_t buffer[39]{};
	const auto string_length = StringFromGUID2(guid, buffer, std::size(buffer));
	FAIL_FAST_IF(string_length != std::size(buffer));

	// remove trailing null when constructing the std::wstring
	std::wstring return_string;
	return_string.assign(buffer, string_length - 1);
	return return_string;
}

enum class PromptResponse : uint8_t
{
	Yes,
	No,
	Skip,
	All,
	// redirected input ran out before an answer; callers treat it as Skip
	EndOfInput
};

//
// PrintDeletionHeader
//
// Prints the heading of one category of rule deletion, with the answers its prompts accept.
//
// Parameters:
//   heading  [in] - the category heading, e.g. "Deleting duplicate rules"
//   prompted [in] - what 'Y' deletes, e.g. "duplicates of the one rule prompted"
//   category [in] - what 'A' deletes, e.g. "duplicate rules"
//
inline void
PrintDeletionHeader(PCSTR heading, PCSTR prompted, PCSTR category) noexcept
{
	std::printf(
	    "     %s - will prompt for input (y/n/s/a)\n"
	    "     - indicate 'Y' to delete %s\n"
	    "     - indicate 'N' to not delete %s\n"
	    "     - indicate 'S' to SKIP deleting any more rules from this store\n"
	    "     - indicate 'A' to delete ALL %s from this store without further prompts\n",
	    heading,
	    prompted,
	    prompted,
	    category);
}
inline constexpr auto* DuplicateDeletionPrompt = "       Delete all duplicates of this rule";
inline constexpr auto* RuleDeletionPrompt = "       Delete this rule";

//
// InputIsConsole
//
// Says whether a prompt's input is the interactive console, which can supply more input after an end
// of input (Ctrl+Z). A file, a pipe, and NUL cannot, and neither can a scripted stream in tests.
//
// Parameters:
//   input [in] - the stream the prompt reads from
//
// Returns:
//   true when input is std::wcin and standard input is a console.
//
inline bool
InputIsConsole(const std::wistream& input) noexcept
{
	DWORD consoleMode{};
	return &input == &std::wcin && GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &consoleMode) != FALSE;
}

//
// AskAgainAtEndOfInput
//
// Decides whether a prompt whose read failed should ask its question again. At the console an end of
// input is not an answer, so the stream is cleared and the question is asked again. Redirected input can
// never supply an answer, so asking again would loop forever; the caller stops asking instead.
//
// Parameters:
//   input          [in, out] - the stream whose read failed; cleared when this returns true
//   inputIsConsole [in] - InputIsConsole(input)
//
// Returns:
//   true when the stream reached its end at the console and was cleared, so the question should be
//   asked again; false when the caller should treat the input as ended.
//
inline bool
AskAgainAtEndOfInput(std::wistream& input, bool inputIsConsole)
{
	if (!inputIsConsole || !input.eof() || input.bad())
	{
		return false;
	}

	input.clear();
	if (&input == &std::wcin)
	{
		// std::wcin reads through stdin, which keeps its own end-of-file flag
		std::clearerr(stdin);
	}
	std::printf("\n");
	return true;
}

//
// PromptForDeletion
//
// Asks whether to delete, until a valid answer is read. At the console an end of input (Ctrl+Z) asks
// again; redirected input that runs out ends the prompt.
//
// Parameters:
//   deletion_prompt [in] - the question, printed before "(y/n/s/a)?"
//   input           [in] - where the answers are read from; tests pass a scripted stream
//
// Returns:
//   The answer. EndOfInput when redirected input runs out, so running out of input never approves a
//   deletion.
//
inline PromptResponse
PromptForDeletion(PCSTR deletion_prompt, std::wistream& input = std::wcin)
{
	std::wstring userInput;
	for (;;)
	{
		std::printf("       %hs (y/n/s/a)? ", deletion_prompt);
		userInput.clear();
		if (!std::getline(input, userInput))
		{
			if (AskAgainAtEndOfInput(input, InputIsConsole(input)))
			{
				continue;
			}

			// running out of input must never count as approving a deletion
			std::printf("\n       - No more input\n");
			return PromptResponse::EndOfInput;
		}

		if (userInput == L"y" || userInput == L"Y")
		{
			return PromptResponse::Yes;
		}
		if (userInput == L"n" || userInput == L"N")
		{
			return PromptResponse::No;
		}

		if (userInput == L"s" || userInput == L"S")
		{
			return PromptResponse::Skip;
		}

		if (userInput == L"a" || userInput == L"A")
		{
			return PromptResponse::All;
		}
	}
}

// by default allow all 4 options (y/n/s/a), but if onlyAllowYesNo is set to true, only allow y/n and ignore s/a inputs (treat them as invalid and re-prompt)
// at the console an end of input (Ctrl+Z) asks again; redirected input that runs out answers No, or Skip
inline PromptResponse
PromptForDeletion(PCWSTR deletion_prompt, bool onlyAllowYesNo = false)
{
	std::wstring userInput;
	for (;;)
	{
		if (onlyAllowYesNo)
		{
			std::printf("%ls (y/n)? ", deletion_prompt);
		}
		else
		{
			std::printf("%ls (y/n/s/a)? ", deletion_prompt);
		}

		userInput.clear();
		if (!std::getline(std::wcin, userInput))
		{
			if (AskAgainAtEndOfInput(std::wcin, InputIsConsole(std::wcin)))
			{
				continue;
			}

			// running out of input must never count as approving a deletion
			std::printf("\n       - No more input\n");
			return onlyAllowYesNo ? PromptResponse::No : PromptResponse::Skip;
		}

		if (userInput == L"y" || userInput == L"Y")
		{
			return PromptResponse::Yes;
		}
		if (userInput == L"n" || userInput == L"N")
		{
			return PromptResponse::No;
		}

		if (onlyAllowYesNo)
		{
			continue;
		}

		if (userInput == L"s" || userInput == L"S")
		{
			return PromptResponse::Skip;
		}

		if (userInput == L"a" || userInput == L"A")
		{
			return PromptResponse::All;
		}
	}
}

class ChronoTimer
{
  public:
	void
	start(PCSTR output_string) noexcept
	{
		if (DebugOutputEnabled())
		{
			m_output_string = output_string;
			m_startTime_ns = std::chrono::high_resolution_clock::now();
		}
	}

	// returns in milliseconds
	void
	end() const noexcept
	{
		if (DebugOutputEnabled())
		{
			const auto endTime_ns = std::chrono::high_resolution_clock::now();
			const auto time =
			    std::chrono::duration_cast<std::chrono::milliseconds>(endTime_ns - m_startTime_ns).count();
			std::printf("<<< %s took %lld ms. >>>\n", m_output_string.c_str(), time);
		}
	}

  private:
	decltype(std::chrono::high_resolution_clock::now()) m_startTime_ns;
	std::string m_output_string;
};
