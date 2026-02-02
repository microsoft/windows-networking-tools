#pragma once
#include <string>
#include <windows.h>

struct NormalizedString
{
	std::wstring value;
	bool containsNonAsciiCharacters{ false };

	~NormalizedString() noexcept = default;

	NormalizedString(const NormalizedString&) = delete;
	NormalizedString& operator=(const NormalizedString&) = delete;

	NormalizedString(NormalizedString&&) noexcept = default;
	NormalizedString& operator=(NormalizedString&&) noexcept = default;

	void append(NormalizedString&& rhs)
	{
		value += std::move(rhs.value);
		containsNonAsciiCharacters = containsNonAsciiCharacters || rhs.containsNonAsciiCharacters;
	}

	// manually copying strings only when asked for explicitly
	// not using copy constructor or copy assignment operator
	void swap(NormalizedString& rhs) noexcept
	{
		NormalizedString& lhs = *this;
		std::swap(lhs.value, rhs.value);
		std::swap(lhs.containsNonAsciiCharacters, rhs.containsNonAsciiCharacters);
	}

	static NormalizedString Copy(const NormalizedString& other)
	{
		NormalizedString copy;
		copy.value = other.value;
		copy.containsNonAsciiCharacters = other.containsNonAsciiCharacters;
		return copy;
	}

	template <typename T>
	static NormalizedString Create(T&& value)
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

private:
	// callers are required to call Create() or Copy() to create an instance
	NormalizedString() noexcept = default;
};

inline bool operator<(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs, rhs) < 0;
}
inline bool operator==(const NormalizedString& lhs, const NormalizedString& rhs) noexcept
{
	return NormalizedString::StringCompare(lhs, rhs) == 0;
}
