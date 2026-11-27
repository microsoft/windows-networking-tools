#pragma once
#include <algorithm>
#include <cassert>
#include <string>
#include <utility>
#include <windows.h>

struct NormalizedString
{
	std::wstring value;
	bool containsNonAsciiCharacters{false};

	NormalizedString() noexcept = default;
	~NormalizedString() noexcept = default;

	NormalizedString(const NormalizedString&) = delete;
	NormalizedString&
	operator=(const NormalizedString&) = delete;

	NormalizedString(NormalizedString&&) noexcept = default;
	NormalizedString&
	operator=(NormalizedString&&) noexcept = default;

	void
	append(const NormalizedString& rhs)
	{
		value += rhs.value;
		containsNonAsciiCharacters = containsNonAsciiCharacters || rhs.containsNonAsciiCharacters;
	}

	// manually copying strings only when asked for explicitly
	// not using copy constructor or copy assignment operator
	void
	swap(NormalizedString& rhs) noexcept
	{
		NormalizedString& lhs = *this;
		std::swap(lhs.value, rhs.value);
		std::swap(lhs.containsNonAsciiCharacters, rhs.containsNonAsciiCharacters);
	}

	static NormalizedString
	Copy(const NormalizedString& other)
	{
		NormalizedString copy;
		copy.value = other.value;
		copy.containsNonAsciiCharacters = other.containsNonAsciiCharacters;
		return copy;
	}

	template <typename T>
	static NormalizedString
	Create(T&& value)
	{
		NormalizedString normalized_string;
		normalized_string.value = std::forward<T>(value);

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

	// returns -1 if lhs < rhs, 0 if lhs == rhs, 1 if lhs > rhs
	static int
	StringCompare(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
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
			return memcmp(lhs.value.c_str(), rhs.value.c_str(), lhs.value.size() * sizeof(wchar_t));
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
			assert(false);
			return 1; // CompareStringOrdinal failed - report the strings as not equal
		}
	}

	// returns -1 if lhs < rhs, 0 if lhs == rhs, 1 if lhs > rhs
	static int
	StringCompare(_In_ PCWSTR lhs, _In_ PCWSTR rhs) noexcept
	{
		if (!lhs && !rhs)
		{
			return 0;
		}

		if (lhs && rhs)
		{
			return StringCompare(Create(lhs), Create(rhs));
		}

		// one is null and the other is not, so the null one is "less than" the non-null one
		return lhs ? 1 : -1;
	}

	//
	// AlphabeticalCompare
	//
	// Orders two strings for display. StringCompare orders shorter strings first, which is faster
	// but not alphabetical; this compares character by character, ignoring case.
	//
	// Parameters:
	//   lhs [in] - a normalized string
	//   rhs [in] - another normalized string
	//
	// Returns:
	//   -1 if lhs sorts before rhs, 0 if they are equal ignoring case, 1 if lhs sorts after rhs.
	//   The order is the same as CompareStringOrdinal with bIgnoreCase: characters are compared as
	//   uppercase, so punctuation such as '_' sorts after the letters. A string sorts before any
	//   longer string that begins with it. Two strings are equal exactly when StringCompare finds
	//   them equal.
	//
	static int
	AlphabeticalCompare(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
	{
		if (!lhs.containsNonAsciiCharacters && !rhs.containsNonAsciiCharacters)
		{
			// compare as uppercase so the ASCII-only order matches CompareStringOrdinal's order for
			// the other strings; otherwise a mix of the two would not sort consistently
			const auto length = (std::min)(lhs.value.size(), rhs.value.size());
			for (size_t index = 0; index < length; ++index)
			{
				const auto left = towupper(lhs.value[index]);
				const auto right = towupper(rhs.value[index]);
				if (left != right)
				{
					return left < right ? -1 : 1;
				}
			}
			if (lhs.value.size() == rhs.value.size())
			{
				return 0;
			}
			return lhs.value.size() < rhs.value.size() ? -1 : 1;
		}

		constexpr BOOL bIgnoreCase = TRUE;
		switch (CompareStringOrdinal(
		    lhs.value.c_str(),
		    static_cast<int>(lhs.value.size()),
		    rhs.value.c_str(),
		    static_cast<int>(rhs.value.size()),
		    bIgnoreCase))
		{
		case CSTR_LESS_THAN:
			return -1;
		case CSTR_EQUAL:
			return 0;
		case CSTR_GREATER_THAN:
			return 1;
		default:
			assert(false);
			return 1; // CompareStringOrdinal failed - report the strings as not equal
		}
	}
	static bool
	StrStrComparison(const NormalizedString& haystack, const NormalizedString& needle) noexcept
	{
		if (haystack.value.empty() || needle.value.empty())
		{
			return haystack.value.empty() && needle.value.empty();
		}

		if (needle.value.size() > haystack.value.size())
		{
			return false;
		}

		if (!haystack.containsNonAsciiCharacters && !needle.containsNonAsciiCharacters)
		{
			// if neither contain non-ascii characters, can just do a raw search without any conversions
			// as they are both already lower-case
			const wchar_t* match = wcsstr(haystack.value.c_str(), needle.value.c_str());
			return match != nullptr;
		}

		// CompareStringOrdinal doesn't have a way to do culture-invariant substring searches, so just do a brute-force search
		const auto& haystackValue = haystack.value;
		const auto& needleValue = needle.value;
		for (size_t i = 0; i <= haystackValue.size() - needleValue.size(); ++i)
		{
			const auto ruleDetailsMatch = CompareStringOrdinal(
			    haystackValue.c_str() + i,
			    static_cast<int>(needleValue.size()),
			    needleValue.c_str(),
			    static_cast<int>(needleValue.size()),
			    TRUE);
			if (ruleDetailsMatch == CSTR_EQUAL)
			{
				return true;
			}
		}
		return false;
	}
};

inline bool
operator<(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs, rhs) < 0;
}
inline bool
operator==(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs, rhs) == 0;
}
