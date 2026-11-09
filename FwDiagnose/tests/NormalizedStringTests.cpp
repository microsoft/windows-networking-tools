// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Unit tests for NormalizedString::StrStrComparison.
// Built by NormalizedStringTests.vcxproj, which is part of the solution. The exit code is nonzero if any test fails.
// Must be compiled with /utf-8 for the non-ASCII string literals to have the expected values.
//
// Strings with embedded null characters are not covered. Callers pass null-terminated names.

#include <cstdio>
#include <string>
#include <vector>

#include "..\NormalizedString.h"

namespace
{
int g_failures = 0;
int g_table_cases = 0;

void
Expect(const std::wstring& haystack, const std::wstring& needle, bool expected, const char* description)
{
	++g_table_cases;
	const auto normalized_haystack = NormalizedString::Create(haystack);
	const auto normalized_needle = NormalizedString::Create(needle);
	const bool actual = NormalizedString::StrStrComparison(normalized_haystack, normalized_needle);
	if (actual != expected)
	{
		++g_failures;
		std::printf("FAIL: %s (expected %d, got %d)\n", description, expected, actual);
	}
}

void
TestEmptyStrings()
{
	Expect(L"", L"", true, "both strings empty");
	Expect(L"", L"a", false, "empty haystack, ASCII needle");
	Expect(L"", L"é", false, "empty haystack, non-ASCII needle");
	Expect(L"a", L"", false, "ASCII haystack, empty needle");
	Expect(L"é", L"", false, "non-ASCII haystack, empty needle");
}

void
TestNeedleLongerThanHaystack()
{
	Expect(L"a", L"ab", false, "ASCII, needle one character longer");
	Expect(L"abc", L"abcdefghijklmnopqrstuvwxyz", false, "ASCII, needle much longer");
	Expect(L"é", L"éa", false, "non-ASCII, needle one character longer");
	Expect(L"é", L"é a much longer needle than the haystack", false, "non-ASCII, needle much longer");
	Expect(L"é.sys", L"a longer ascii driver name", false, "non-ASCII haystack, longer ASCII needle");
	Expect(L"a.sys", L"café driver with a long name", false, "ASCII haystack, longer non-ASCII needle");
}

void
TestAsciiSearch()
{
	Expect(L"driver.sys", L"driver", true, "ASCII match at the start");
	Expect(L"my.driver.sys", L"driver", true, "ASCII match in the middle");
	Expect(L"my.driver", L"driver", true, "ASCII match at the end");
	Expect(L"driver", L"driver", true, "ASCII equal strings");
	Expect(L"DRIVER.SYS", L"driver", true, "ASCII upper-case haystack");
	Expect(L"driver.sys", L"DRIVER", true, "ASCII upper-case needle");
	Expect(L"driver.sys", L"other", false, "ASCII no match");
	Expect(L"driver", L"drivex", false, "ASCII equal length, last character differs");
	Expect(L"aaab", L"aab", true, "ASCII overlapping partial match");
}

void
TestNonAsciiSearch()
{
	Expect(L"café.sys", L"café", true, "non-ASCII match at the start");
	Expect(L"my café driver", L"café", true, "non-ASCII match in the middle");
	Expect(L"my café", L"café", true, "non-ASCII match at the very end");
	Expect(L"café", L"café", true, "non-ASCII equal strings");
	Expect(L"café", L"cafè", false, "non-ASCII equal length, last character differs");
	Expect(L"CAFÉ.SYS", L"café", true, "non-ASCII upper-case haystack");
	Expect(L"café.sys", L"CAFÉ", true, "non-ASCII upper-case needle");
	Expect(L"café.sys", L"driver", false, "non-ASCII haystack, ASCII needle, no match");
	Expect(L"driver.sys", L"café", false, "ASCII haystack, non-ASCII needle, no match");
	Expect(L"café DRIVER", L"driver", true, "ASCII needle after the first non-ASCII character");
	Expect(L"ééè", L"éè", true, "non-ASCII overlapping partial match");
	Expect(L"日本語", L"本", true, "non-Latin match");
}

void
TestOrdinalComparison()
{
	// comparisons are ordinal: there are no linguistic equivalences
	Expect(L"straße", L"strasse", false, "sharp s does not expand to ss");
	Expect(L"strasse!", L"straße", false, "ss does not match sharp s");
	Expect(L"İx", L"ix", false, "dotted capital I does not match i");
	Expect(L"café", L"cafe", false, "accented character does not match its base letter");
	Expect(L"café", L"café", false, "combining sequence does not match its composed form");
}

void
TestSurrogatePairs()
{
	Expect(L"a\U0001F600b", L"\U0001F600", true, "surrogate pair in the middle");
	Expect(L"a\U0001F600", L"\U0001F600", true, "surrogate pair at the end");
	Expect(L"a\U0001F600b", L"\U0001F601", false, "different surrogate pair");
}

void
TestLongStrings()
{
	const std::wstring prefix(10000, L'x');
	Expect(prefix + L"é", L"xé", true, "non-ASCII match at the end of a long string");
	Expect(prefix + L"y", L"xy", true, "ASCII match at the end of a long string");
	Expect(prefix, prefix + L"é", false, "long non-ASCII needle, one character longer");
}

constexpr wchar_t lower_e_acute = 0x00e9;
constexpr wchar_t upper_e_acute = 0x00c9;

wchar_t
FoldForReference(wchar_t character) noexcept
{
	switch (character)
	{
	case L'A':
		return L'a';
	case upper_e_acute:
		return lower_e_acute;
	default:
		return character;
	}
}

std::wstring
FoldForReference(const std::wstring& value)
{
	std::wstring folded{value};
	for (auto& character : folded)
	{
		character = FoldForReference(character);
	}
	return folded;
}

// the expected result, computed without using any of the code under test
bool
ReferenceResult(const std::wstring& haystack, const std::wstring& needle)
{
	if (haystack.empty() || needle.empty())
	{
		return haystack.empty() && needle.empty();
	}
	return FoldForReference(haystack).find(FoldForReference(needle)) != std::wstring::npos;
}

std::vector<std::wstring>
AllStringsUpToLength(size_t max_length)
{
	static constexpr wchar_t alphabet[]{L'a', L'A', L'b', lower_e_acute, upper_e_acute};

	std::vector<std::wstring> strings{L""};
	size_t begin = 0;
	for (size_t length = 1; length <= max_length; ++length)
	{
		const auto end = strings.size();
		for (auto index = begin; index < end; ++index)
		{
			for (const auto character : alphabet)
			{
				strings.push_back(strings[index] + character);
			}
		}
		begin = end;
	}
	return strings;
}

size_t
TestAllShortStrings()
{
	const auto haystacks = AllStringsUpToLength(5);
	const auto needles = AllStringsUpToLength(5);

	std::vector<NormalizedString> normalized_needles;
	normalized_needles.reserve(needles.size());
	for (const auto& needle : needles)
	{
		normalized_needles.emplace_back(NormalizedString::Create(needle));
	}

	size_t combinations = 0;
	for (const auto& haystack : haystacks)
	{
		const auto normalized_haystack = NormalizedString::Create(haystack);
		for (size_t index = 0; index < needles.size(); ++index)
		{
			++combinations;
			if (NormalizedString::StrStrComparison(normalized_haystack, normalized_needles[index]) !=
			    ReferenceResult(haystack, needles[index]))
			{
				++g_failures;
				if (g_failures <= 20)
				{
					std::printf("FAIL: exhaustive case %zu did not match the reference result\n", combinations);
				}
			}
		}
	}
	return combinations;
}
} // namespace

int
wmain()
{
	TestEmptyStrings();
	TestNeedleLongerThanHaystack();
	TestAsciiSearch();
	TestNonAsciiSearch();
	TestOrdinalComparison();
	TestSurrogatePairs();
	TestLongStrings();
	const auto combinations = TestAllShortStrings();

	std::printf("%d table cases, %zu exhaustive combinations, %d failures\n", g_table_cases, combinations, g_failures);
	return g_failures == 0 ? 0 : 1;
}
