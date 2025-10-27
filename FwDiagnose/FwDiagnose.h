// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <string>
#include <chrono>
#include <iostream>

#include <Windows.h>

bool DebugPrintEnabled() noexcept;
bool CleanBrokenRulesEnabled() noexcept;
bool VerboseOutputEnabled() noexcept;
bool WfpOutputEnabled() noexcept;

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

class ChronoTimer
{
public:
	void start(PCSTR output_string) noexcept
	{
		if (DebugPrintEnabled())
		{
			m_output_string = output_string;
			m_startTime_ns = std::chrono::high_resolution_clock::now();
		}
	}

	// returns in milliseconds
	void end() const noexcept
	{
		if (DebugPrintEnabled())
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

struct NormalizedString
{
	std::wstring value;
	bool containsNonAsciiCharacters{ false };

	NormalizedString() noexcept = default;
	~NormalizedString() noexcept = default;

	NormalizedString(const NormalizedString&) = delete;
	NormalizedString& operator=(const NormalizedString&) = delete;
	NormalizedString(NormalizedString&&) noexcept = default;
	NormalizedString& operator=(NormalizedString&&) noexcept = default;

	explicit NormalizedString(std::wstring str) : value(std::move(str))
	{
	}

	void operator+=(const NormalizedString& rhs)
	{
		value += rhs.value;
		containsNonAsciiCharacters = containsNonAsciiCharacters || rhs.containsNonAsciiCharacters;
	}

	// manually copying strings only when asked for explicitly
	// not using copy constructor or copy assignment operator

	static NormalizedString Copy(const NormalizedString& other)
	{
		NormalizedString copy;
		copy.value = other.value;
		copy.containsNonAsciiCharacters = other.containsNonAsciiCharacters;
		return copy;
	}

	static NormalizedString Normalize(const std::wstring& value)
	{
		NormalizedString normalized_string{ value };

		// if is an ASCII character (ANSI code page) then can trivially convert to lower-case
		// and can avoid a more expensive call to CompareStringOrdinal
		for (auto& character : normalized_string.value)
		{
			if (iswascii(character))
			{
				// towlower only works on ASCII characters
				character = towlower(character);
			}
			else
			{
				// if hit any non-ascii character, just break from the loop
				normalized_string.containsNonAsciiCharacters = true;
				break;
			}
		}

		return normalized_string;
	}
	static int StringCompare(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
	{
		if (lhs.value.size() != rhs.value.size())
		{
			return lhs.value.size() < rhs.value.size() ? -1 : 1;
		}
		if (lhs.value.empty() && rhs.value.empty())
		{
			return 0;
		}

		// if all ascii characters, can just do a raw memcmp without any conversions
		if (!lhs.containsNonAsciiCharacters && !rhs.containsNonAsciiCharacters)
		{
			return memcmp(
				lhs.value.c_str(),
				rhs.value.c_str(),
				lhs.value.size() * sizeof(wchar_t));
		}

		constexpr BOOL bIgnoreCase = TRUE;
		const auto ruleDetailsMatch = CompareStringOrdinal(
			lhs.value.c_str(),
			static_cast<int>(lhs.value.size()),
			rhs.value.c_str(),
			static_cast<int>(rhs.value.size()),
			bIgnoreCase);
		switch (ruleDetailsMatch)
		{
		case CSTR_LESS_THAN:
			return -1;
		case CSTR_EQUAL:
			return 0;
		case CSTR_GREATER_THAN:
			return 1;
		default:
			DebugBreak();
			return 1; // should never reach here
		}
	}
};

inline bool operator<(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs, rhs) < 0;
}
inline bool operator==(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs, rhs) == 0;
}

