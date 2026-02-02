// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <string>
#include <chrono>
#include <iostream>

#include <Windows.h>

bool DebugOutputEnabled() noexcept;
bool VerboseOutputEnabled() noexcept;
bool AnalyzeRulesEnabled() noexcept;
bool CleanBrokenRulesEnabled() noexcept;

bool WfpOutputEnabled() noexcept;
bool WfpEventEnumerationEnabled() noexcept;
bool RemoveWfpCalloutFiltersEnabled() noexcept;

enum class PromptResponse
{
	Yes,
	No,
	Skip,
	All
};
inline PromptResponse PromptForDeletion(PCSTR deletion_prompt)
{
	std::wstring userInput;
	for (;;)
	{
		std::printf("       %hs (y/n/s/a)? ", deletion_prompt);
		userInput.clear();
		std::getline(std::wcin, userInput);

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
inline PromptResponse PromptForDeletion(PCWSTR deletion_prompt)
{
	std::wstring userInput;
	for (;;)
	{
		std::printf("       %ls (y/n/s/a)? ", deletion_prompt);
		userInput.clear();
		std::getline(std::wcin, userInput);

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

class ChronoTimer
{
public:
	void start(PCSTR output_string) noexcept
	{
		if (DebugOutputEnabled())
		{
			m_output_string = output_string;
			m_startTime_ns = std::chrono::high_resolution_clock::now();
		}
	}

	// returns in milliseconds
	void end() const noexcept
	{
		if (DebugOutputEnabled())
		{
			const auto endTime_ns = std::chrono::high_resolution_clock::now();
			const auto time = std::chrono::duration_cast<std::chrono::milliseconds>(endTime_ns - m_startTime_ns).count();
			std::printf("<<< %s took %lld ms. >>>\n", m_output_string.c_str(), time);
		}
	}

private:
	decltype(std::chrono::high_resolution_clock::now()) m_startTime_ns;
	std::string m_output_string;
};
