// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Unit tests for NormalizedString::StrStrComparison and NormalizedString::AlphabeticalCompare.
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

//
// ExpectOrder
//
// Checks AlphabeticalCompare in both directions.
//
// Parameters:
//   lhs         [in] - a string
//   rhs         [in] - another string
//   expected    [in] - -1, 0, or 1: how lhs should compare with rhs
//   description [in] - printed when the check fails
//
void
ExpectOrder(const std::wstring& lhs, const std::wstring& rhs, int expected, const char* description)
{
	++g_table_cases;
	const auto normalized_lhs = NormalizedString::Create(lhs);
	const auto normalized_rhs = NormalizedString::Create(rhs);
	const auto forward = NormalizedString::AlphabeticalCompare(normalized_lhs, normalized_rhs);
	const auto reverse = NormalizedString::AlphabeticalCompare(normalized_rhs, normalized_lhs);
	if (forward != expected || reverse != -expected)
	{
		++g_failures;
		std::printf("FAIL: %s (expected %d, got %d and reversed %d)\n", description, expected, forward, reverse);
	}
}

//
// TestAlphabeticalOrder
//
// Checks the cases where alphabetical order differs from StringCompare's shorter-first order.
//
void
TestAlphabeticalOrder()
{
	ExpectOrder(L"zz", L"aaa", 1, "a shorter string is not ordered first");
	ExpectOrder(L"alpha", L"Beta", -1, "case is ignored when ordering");
	ExpectOrder(L"ABC", L"abc", 0, "strings differing only in case are equal");
	ExpectOrder(L"ab", L"abc", -1, "a string sorts before a longer string that begins with it");
	ExpectOrder(L"", L"a", -1, "the empty string sorts first");
	ExpectOrder(L"", L"", 0, "empty strings are equal");
	ExpectOrder(L"a_", L"az", 1, "'_' sorts after the letters, as in CompareStringOrdinal");
	ExpectOrder(L"_é", L"a", 1, "'_' sorts after the letters in a non-ASCII string too");
	ExpectOrder(L"café", L"cafz", 1, "a non-ASCII character sorts after the ASCII letters");
	ExpectOrder(L"CAFÉ", L"café", 0, "non-ASCII strings differing only in case are equal");
}

//
// TestAllShortStringOrders
//
// Compares every pair of short strings, ASCII-only and not, with CompareStringOrdinal (ignoring
// case) on the original strings. Agreeing for every pair also means the order is consistent
// enough to sort with.
//
// Returns:
//   The number of pairs compared.
//
size_t
TestAllShortStringOrders()
{
	static constexpr wchar_t alphabet[]{L'a', L'A', L'_', lower_e_acute, upper_e_acute};
	std::vector<std::wstring> strings{L""};
	for (size_t begin = 0, length = 1; length <= 3; ++length)
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

	size_t pairs = 0;
	for (const auto& lhs : strings)
	{
		const auto normalized_lhs = NormalizedString::Create(lhs);
		for (const auto& rhs : strings)
		{
			++pairs;
			const auto reference = CompareStringOrdinal(
			                           lhs.c_str(),
			                           static_cast<int>(lhs.size()),
			                           rhs.c_str(),
			                           static_cast<int>(rhs.size()),
			                           TRUE) -
			                       CSTR_EQUAL;
			const auto normalized_rhs = NormalizedString::Create(rhs);
			const auto actual = NormalizedString::AlphabeticalCompare(normalized_lhs, normalized_rhs);
			const auto equal = NormalizedString::StringCompare(normalized_lhs, normalized_rhs) == 0;
			if (actual != reference || (actual == 0) != equal)
			{
				++g_failures;
				if (g_failures <= 20)
				{
					std::printf("FAIL: ordering pair %zu did not match CompareStringOrdinal or StringCompare\n", pairs);
				}
			}
		}
	}
	return pairs;
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
	TestAlphabeticalOrder();
	const auto pairs = TestAllShortStringOrders();

	std::printf(
	    "%d table cases, %zu exhaustive combinations, %zu exhaustive ordering pairs, %d failures\n",
	    g_table_cases,
	    combinations,
	    pairs,
	    g_failures);
	return g_failures == 0 ? 0 : 1;
}
