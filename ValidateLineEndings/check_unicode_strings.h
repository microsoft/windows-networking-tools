#pragma once
#include <algorithm>
#include <array>
#include <string_view>
#include <vector>

constexpr uint8_t FORM_FEED_CHARACTER = 0x0C;
constexpr uint8_t SUBSTITUTION_CHARACTER = 0x1A;

constexpr uint8_t CR = 0x0D; // '\r'
constexpr uint8_t LF = 0x0A; // '\n'

enum class BomType {
	None,
	UTF8,
	UTF16_LE,
	UTF16_BE,
	None_UTF16_LE_Formatted
};

class Utf16Checker {
public:
	static bool IsUtf16Allowed(const std::filesystem::path& filepath) noexcept
	{
		using namespace std::string_view_literals;
		static constexpr std::array utf16_file_extensions_allowed{
			L""sv,
			L".cs"sv,
			L".csproj"sv,
			L".csv"sv,
			L".idl"sv,
			L".ini"sv,
			L".rc"sv,
			L".rdp"sv,
			L".wtl"sv,
			L".xml"sv,
		};
		static_assert(std::ranges::is_sorted(utf16_file_extensions_allowed));

		return (
			filepath.has_extension()
			&&
			std::ranges::binary_search(
				utf16_file_extensions_allowed,
				filepath.extension().wstring()));
	}

	static BomType Utf16Bom(const std::vector<uint8_t>& buffer) noexcept
	{
		if (buffer.size() > 1) {
			const auto first_character = buffer[0];
			const auto second_character = buffer[1];
			if (first_character == 0xFF && second_character == 0xFE)
			{
				return BomType::UTF16_LE;
			}
			else if (first_character == 0xFE && second_character == 0xFF)
			{
				return BomType::UTF16_BE;
			}
		}
		return BomType::None;
	}

	static bool NullByteAsPartOfUtf16Encoding(const std::filesystem::path& filepath, uint8_t ch) noexcept
	{
		// UTF-16 file without BOM for known file types
		// - allow null bytes as part of the multibyte encoding
		return ((ch == 0x00) && IsUtf16Allowed(filepath));
	}
};

constexpr uint8_t bom_utf8_a = 0xEF;
constexpr uint8_t bom_utf8_b = 0xBB;
constexpr uint8_t bom_utf8_c = 0xBF;
class Utf8Checker {
public:
	static bool HasUtf8Bom(const std::vector<uint8_t>& buffer) noexcept
	{
		if (buffer.size() > 2) {
			const auto first_character = buffer[0];
			const auto second_character = buffer[1];
			const auto third_character = buffer[2];

			if (first_character == bom_utf8_a &&
				second_character == bom_utf8_b &&
				third_character == bom_utf8_c)
			{
				return true;
			}
		}
		return false;
	}

	enum class ManuallyRemoveCharacterCheckerResult {
		None,
		FormFeed,
		Substitute
	};
	static ManuallyRemoveCharacterCheckerResult IsCharToManuallyRemove(uint8_t ch) noexcept
	{
		if (ch == FORM_FEED_CHARACTER) {
			return ManuallyRemoveCharacterCheckerResult::FormFeed;
		}
		if (ch == SUBSTITUTION_CHARACTER) {
			return ManuallyRemoveCharacterCheckerResult::Substitute;
		}
		return ManuallyRemoveCharacterCheckerResult::None;
	}

	static bool IsPrintableCharacter(uint8_t ch) noexcept
	{
		// allow for the tab character
		// allow CR and LF line endings
		// [0x20, 0x7E] are the printable characters, including the space character.
		// https://en.wikipedia.org/wiki/ASCII#Printable_characters
		// [0xA0, 0xBF] are additional printable characters in Latin-1 Supplement block.

		return (
			ch == 0x09 || // TAB
			ch == 0x0A || // LF
			ch == 0x0D || // CR
			(ch >= 0x20 && ch <= 0x7E) || // printable ASCII characters
			(ch >= 0xA0 && ch <= 0xBF));  // additional printable characters in Latin-1 Supplement block
	}

	bool IsContinuationOrSequenceByte(uint8_t ch) noexcept
	{
		const auto update_tracking_on_exit = wil::scope_exit([&]() {
			update_tracking_fields(ch);
			});

		if ((ch >= 0x80 && ch <= 0xBF) || (previous >= 0x80 && previous <= 0xBF)) {
			// UTF-8 continuation byte
			return true;
		}

		if ((ch >= 0xC0 && ch <= 0xDF) || (previous >= 0xC0 && previous <= 0xDF))
		{
			// this signals the character is part of a 2-char multibyte UTF-8 sequence
			return true;
		}

		if ((ch >= 0xE0 && ch <= 0xEF) ||
			(previous >= 0xE0 && previous <= 0xEF) ||
			(previous2 >= 0xE0 && previous2 <= 0xEF)) {
			// this signals the character is part of a 3-char multibyte UTF-8 sequence
			return true;
		}

		if ((ch >= 0xF0 && ch <= 0xF7) ||
			(previous >= 0xF0 && previous <= 0xF7) ||
			(previous2 >= 0xF0 && previous2 <= 0xF7) ||
			(previous3 >= 0xF0 && previous3 <= 0xF7)) {
			// this signals the character is part of a 4-char multibyte UTF-8 sequence
			return true;
		}

		if ((ch >= 0xF8 && ch <= 0xFB) ||
			(previous >= 0xF8 && previous <= 0xFB) ||
			(previous2 >= 0xF8 && previous2 <= 0xFB) ||
			(previous3 >= 0xF8 && previous3 <= 0xFB) ||
			(previous4 >= 0xF8 && previous4 <= 0xFB)) {
			// this signals the character is part of a 5-char multibyte UTF-8 sequence
			return true;
		}

		if ((ch >= 0xFC && ch <= 0xFD) ||
			(previous >= 0xFC && previous <= 0xFD) ||
			(previous2 >= 0xFC && previous2 <= 0xFD) ||
			(previous3 >= 0xFC && previous3 <= 0xFD) ||
			(previous4 >= 0xFC && previous4 <= 0xFD) ||
			(previous5 >= 0xFC && previous5 <= 0xFD)) {
			// this signals the character is part of a 6-char multibyte UTF-8 sequence
			return true;
		}

		return false;
	}

private:
	uint8_t previous = 0x00;
	uint8_t previous2 = 0x00;
	uint8_t previous3 = 0x00;
	uint8_t previous4 = 0x00;
	uint8_t previous5 = 0x00;

	void update_tracking_fields(uint8_t ch)
	{
		previous5 = previous4;
		previous4 = previous3;
		previous3 = previous2;
		previous2 = previous;
		previous = ch;
	}
};

inline BomType GetBomType(const std::vector<uint8_t>& buffer) noexcept
{
	if (Utf8Checker::HasUtf8Bom(buffer))
	{
		return BomType::UTF8;
	}

	const auto utf16_bom = Utf16Checker::Utf16Bom(buffer);
	if (utf16_bom == BomType::UTF16_LE || utf16_bom == BomType::UTF16_BE)
	{
		return utf16_bom;
	}

	// check for UTF-16 LE formatted file without BOM
	bool has_utf16_le_pattern = true;
	for (size_t count = 0; count < buffer.size(); ++count)
	{
		// quick check for a UTF16 formatted string: every other char is 0x00
		if (count % 2 == 1)
		{
			if (buffer[count] != 0)
			{
				has_utf16_le_pattern = false;
				break;
			}
		}
	}

	return has_utf16_le_pattern ? BomType::None_UTF16_LE_Formatted : BomType::None;
}

