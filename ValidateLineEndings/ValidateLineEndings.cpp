#include <algorithm>
#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <print>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
#include <wil/resource.h>

#include "binaryfilereader.h"
#include "check_unicode_strings.h"
#include "skipped_files.h"

using namespace std;

static std::atomic g_validation_failure_count = 0;
static std::atomic g_validation_logged_count = 0;
static std::atomic g_validation_manual_update_count = 0;

static bool g_fix_form_feed_chars = false;
static bool g_fix_substitute_chars = false;
static bool g_process_damaged_crlf = false;
static bool g_process_disallowed_chars = false;

static bool g_fix_file_damaged_crlf = false;
static bool g_fix_disallowed_chars = false;

static std::vector<std::wstring> g_allowed_file_extensions_for_fixing_disallowed_chars;
static std::vector<std::wstring> g_blocked_file_extensions_for_fixing_disallowed_chars;

constexpr auto* g_log_filename = L"validation_failures.log";
constexpr auto* g_log_filename_formatted = L".\\validation_failures.log";
static ofstream g_log_file;

template <class... Args>
static void print_validation_failure(
	const filesystem::path& filepath,
	format_string<type_identity_t<Args>...> fmt, Args&&... args)
{
	print(stderr, "{} : ", filepath.string());
	println(stderr, fmt, std::forward<Args>(args)...);
	++g_validation_failure_count;
}

template <class... Args>
static void log_validation_failure(
	const filesystem::path& filepath,
	format_string<type_identity_t<Args>...> fmt, Args&&... args)
{
	g_log_file << format("{} : ", filepath.string());
	g_log_file << format(fmt, std::forward<Args>(args)...);
	g_log_file << '\r' << '\n';
	++g_validation_logged_count;
}

static bool ShouldAutomaticallyFixFile(const filesystem::path& filepath)
{
	const auto is_blocked = g_blocked_file_extensions_for_fixing_disallowed_chars.cend() != std::find(
		g_blocked_file_extensions_for_fixing_disallowed_chars.cbegin(),
		g_blocked_file_extensions_for_fixing_disallowed_chars.cend(),
		filepath.extension());
	if (is_blocked)
	{
		println(" - skipping the file ({}) from fixing disallowed characters.", filepath.string());
		return false;
	}

	const auto is_allowed = g_allowed_file_extensions_for_fixing_disallowed_chars.cend() != std::find(
		g_allowed_file_extensions_for_fixing_disallowed_chars.cbegin(),
		g_allowed_file_extensions_for_fixing_disallowed_chars.cend(),
		filepath.extension());
	if (is_allowed)
	{
		return true;
	}

	// else prompt the user to allow that file extension
	print(" * Should files with the extension ({}) be allowed to automatically be fixed? (y/n) ",
		filepath.extension().string());

	std::string response;
	std::getline(std::cin, response);
	if (!response.empty() && (response[0] == 'y' || response[0] == 'Y'))
	{
		g_allowed_file_extensions_for_fixing_disallowed_chars.push_back(filepath.extension().wstring());
		return true;
	}
	else
	{
		g_blocked_file_extensions_for_fixing_disallowed_chars.push_back(filepath.extension().wstring());
		println(" - skipping the file for fixing disallowed characters.");
		return false;
	}
}

static void ShellExecutePath(_In_ PCWSTR path) noexcept
{
	SHELLEXECUTEINFOW shell_exec{};
	shell_exec.cbSize = sizeof(SHELLEXECUTEINFOW);
	shell_exec.lpVerb = L"open";
	shell_exec.lpFile = path;
	shell_exec.nShow = SW_SHOWNORMAL;
	if (!ShellExecuteExW(&shell_exec))
	{
		const auto gle = GetLastError();
		println("ShellExecuteEx failed - gle {} ShellError {}", gle, reinterpret_cast<uintptr_t>(shell_exec.hInstApp));
	}
	else
	{
		print("Hit Enter key after fixing the files .. ");
		std::string str;
		std::getline(std::cin, str);
		println(" .. resuming");
	}
}

static void FixUtf16BomInFile(const filesystem::path& filepath)
{
	WCHAR temp_filename[MAX_PATH]{};
	const auto temp_filename_error = GetTempFileName(L".", L"", 0, temp_filename);
	if (temp_filename_error == 0)
	{
		const auto gle = GetLastError();
		println(stderr, "Failed GetTempFileName: {}", gle);
		return;
	}

	wil::unique_hfile temp_file_handle{ CreateFile(temp_filename, GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) };
	if (!temp_file_handle)
	{
		const auto gle = GetLastError();
		println(stderr, "Failed CreateFile: {}", gle);
		return;
	}

	const auto always_delete_temp_file = wil::scope_exit([&] {
		DeleteFile(temp_filename);
		});

	// write the BOM
	std::vector<uint8_t> modified_buffer;
	modified_buffer.push_back(0xFF);
	modified_buffer.push_back(0xFE);
	if (!WriteFile(
		temp_file_handle.get(),
		modified_buffer.data(),
		static_cast<DWORD>(modified_buffer.size()),
		nullptr,
		nullptr))
	{
		THROW_LAST_ERROR();
	}

	// now write the rest of the file
	vector<uint8_t> buffer;
	for (BinaryFileReader binary_file{ filepath }; binary_file.read_next_block(buffer);)
	{
		if (!WriteFile(
			temp_file_handle.get(),
			buffer.data(),
			static_cast<DWORD>(buffer.size()),
			nullptr,
			nullptr))
		{
			THROW_LAST_ERROR();
		}
	}

	// close the handle to our temp file, and move it over to the original file
	temp_file_handle.reset();

	println("Replacing {}", filepath.string());
	if (!MoveFileEx(temp_filename, filepath.c_str(), MOVEFILE_REPLACE_EXISTING))
	{
		const auto gle = GetLastError();
		println("Failed MoveFileEx({}, {}) : {}", filesystem::path{ temp_filename }.string(), filepath.string(), gle);
	}
}

static void FixCrlfInFile(const filesystem::path& filepath)
{
	WCHAR temp_filename[MAX_PATH]{};
	const auto temp_filename_error = GetTempFileName(L".", L"", 0, temp_filename);
	if (temp_filename_error == 0)
	{
		const auto gle = GetLastError();
		println(stderr, "Failed GetTempFileName: {}", gle);
		return;
	}

	wil::unique_hfile temp_file_handle{ CreateFile(temp_filename, GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) };
	if (!temp_file_handle)
	{
		const auto gle = GetLastError();
		println(stderr, "Failed CreateFile: {}", gle);
		return;
	}

	const auto always_delete_temp_file = wil::scope_exit([&] {
		DeleteFile(temp_filename);
		});

	std::vector<uint8_t> modified_buffer;
	modified_buffer.resize(static_cast<uint32_t>(BinaryFileReader::BlockSize * 1.25));

	vector<uint8_t> buffer;
	uint8_t previous_character{};
	for (BinaryFileReader binary_file{ filepath }; binary_file.read_next_block(buffer);)
	{
		modified_buffer.clear();
		previous_character = 0x00;

		// require a CRLF
		// - if a CR and the next character is not an LF, fix it
		// - if a LF and the previous character is not a CR, fix it
		for (unsigned char current_character : buffer)
		{
			if (previous_character == CR && current_character != LF)
			{
				// add an LF after the CR - before the current_character
				modified_buffer.push_back(LF);
			}
			else if (current_character == LF && previous_character != CR)
			{
				// add a CR before the LF (LF is the current_character)
				modified_buffer.push_back(CR);
			}

			modified_buffer.push_back(current_character);
			previous_character = current_character;
		}

		if (!WriteFile(
			temp_file_handle.get(),
			modified_buffer.data(),
			static_cast<DWORD>(modified_buffer.size()),
			nullptr,
			nullptr))
		{
			THROW_LAST_ERROR();
		}
	}

	if (previous_character == CR) { // file ends with CR
		modified_buffer.clear();
		modified_buffer.push_back(LF);
		if (!WriteFile(
			temp_file_handle.get(),
			modified_buffer.data(),
			static_cast<DWORD>(modified_buffer.size()),
			nullptr,
			nullptr))
		{
			THROW_LAST_ERROR();
		}
	}

	// close the handle to our temp file, and move it over to the original file
	temp_file_handle.reset();

	println("Replacing {}", filepath.string());
	if (!MoveFileEx(temp_filename, filepath.c_str(), MOVEFILE_REPLACE_EXISTING))
	{
		const auto gle = GetLastError();
		println("Failed MoveFileEx({}, {}) : {}", filesystem::path{ temp_filename }.string(), filepath.string(), gle);
	}
}

static void RemoveCharInFile(const filesystem::path& filepath, uint8_t char_to_remove)
{
	vector<uint8_t> buffer;
	buffer.resize(BinaryFileReader::BlockSize);

	WCHAR temp_filename[MAX_PATH]{};
	const auto temp_filename_error = GetTempFileName(L".", L"", 0, temp_filename);
	if (temp_filename_error == 0)
	{
		const auto gle = GetLastError();
		println(stderr, "Failed GetTempFileName: {}", gle);
		return;
	}

	wil::unique_hfile temp_file_handle{ CreateFile(temp_filename, GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) };
	if (!temp_file_handle)
	{
		const auto gle = GetLastError();
		println(stderr, "Failed CreateFile: {}", gle);
		return;
	}

	const auto always_delete_temp_file = wil::scope_exit([&] {
		DeleteFile(temp_filename);
		});

	bool file_fixed = false;
	bool bom_checked = false;
	for (BinaryFileReader binary_file{ filepath }; binary_file.read_next_block(buffer);) {
		if (!bom_checked)
		{
			if (Utf16Checker::Utf16Bom(buffer) != BomType::None)
			{
				return; // skip UTF-16 files
			}
			bom_checked = true;
		}

		if (std::erase_if(buffer, [&](const auto lhs) { return lhs == char_to_remove; }) > 0)
		{
			file_fixed = true;
		}

		WriteFile(
			temp_file_handle.get(),
			buffer.data(),
			static_cast<DWORD>(buffer.size()),
			nullptr,
			nullptr);
		buffer.resize(BinaryFileReader::BlockSize);
	}

	// close the handle to our temp file, and move it over to the original file
	temp_file_handle.reset();

	if (file_fixed)
	{
		println("Replacing {}", filepath.string());
		if (!MoveFileEx(temp_filename, filepath.c_str(), MOVEFILE_REPLACE_EXISTING))
		{
			const auto gle = GetLastError();
			println("Failed MoveFileEx({}, {}) : {}", filesystem::path{ temp_filename }.string(), filepath.string(), gle);
		}
	}
}

static void scan_file(const filesystem::path& filepath, vector<uint8_t>& buffer)
{
	bool file_has_single_cr = false;
	bool file_has_single_lf = false;
	bool file_has_crlf = false;

	bool file_has_form_feed_chars_to_be_manually_removed = false;
	bool file_has_substitute_chars_to_be_manually_removed = false;
	const auto log_manual_remove_chars_at_exit = wil::scope_exit([&]() {
		if (file_has_form_feed_chars_to_be_manually_removed) {
			++g_validation_manual_update_count;
			log_validation_failure(filepath, "file contains the 0x0C (form feed) character that need to be removed separately (-fix-form-feed)");
		}
		if (file_has_substitute_chars_to_be_manually_removed) {
			if (!file_has_form_feed_chars_to_be_manually_removed)
			{
				++g_validation_manual_update_count;
			}
			log_validation_failure(filepath, "file contains the 0x1A (substitute) character that need to be removed separately (-fix-substitute)");
		}
		});

	// first get the BOM type
	BinaryFileReader bom_check_file{ filepath };
	if (!bom_check_file.read_next_block(buffer))
	{
		// file is empty
		return;
	}
	BomType bom_type = GetBomType(buffer);
	bom_check_file.close_handle();

	// not scanning known UTF16 files
	if (bom_type == BomType::UTF16_LE)
	{
		if (!Utf16Checker::IsUtf16Allowed(filepath))
		{
			log_validation_failure(filepath, "file contains UTF-16 LE BOM - skipping");
		}
		return;
	}
	if (bom_type == BomType::UTF16_BE)
	{
		if (!Utf16Checker::IsUtf16Allowed(filepath))
		{
			log_validation_failure(filepath, "file contains UTF-16 BE BOM - skipping");
		}
		return;
	}

	// if the file looks like a UTF16LE formatted file - give it a BOM
	// then exit - not supporting scanning of UTF16 files
	if (bom_type == BomType::None_UTF16_LE_Formatted)
	{
		if (g_fix_file_damaged_crlf)
		{
			println("{} looks to have a UTF16-LE text pattern", filepath.string());
			if (ShouldAutomaticallyFixFile(filepath))
			{
				FixUtf16BomInFile(filepath);
			}
		}
		else
		{
			println("{} looks to have a UTF16-LE text pattern - skipping (specify -fix-damaged-crlf to automatically fix it)", filepath.string());
		}
		return;
	}

	size_t file_offset = 0;
	size_t current_line = 1;
	size_t disallowed_character_count = 0;
	Utf8Checker utf8_checker;
	uint8_t previous_ch = '\0';
	for (BinaryFileReader binary_file{ filepath }; binary_file.read_next_block(buffer);) {
		for (const auto& ch : buffer) {
			++file_offset;
			if (file_offset <= 3 && bom_type == BomType::UTF8) {
				// skip UTF-8 BOM characters
				continue;
			}

			if (previous_ch == CR) {
				if (ch == LF) {
					file_has_crlf = true;
					++current_line;
				}
				else {
					file_has_single_cr = true;
					++current_line;
				}
			}
			else if (ch == LF) {
				file_has_single_lf = true;
				++current_line;
			}
			previous_ch = ch;

			// flag the character if:
			// - it's not printable
			// - it's not part of a UTF-8 multibyte sequence
			// - it does not look like UTF-16 encoding in a file that didn't have the UTF-16 BOM
			if (!Utf8Checker::IsPrintableCharacter(ch) &&
				!utf8_checker.IsContinuationOrSequenceByte(ch) &&
				!Utf16Checker::NullByteAsPartOfUtf16Encoding(filepath, ch))
			{
				const auto utf8_manual_check = Utf8Checker::IsCharToManuallyRemove(ch);
				if (utf8_manual_check == Utf8Checker::ManuallyRemoveCharacterCheckerResult::FormFeed) {
					file_has_form_feed_chars_to_be_manually_removed = true;
				}
				else if (utf8_manual_check == Utf8Checker::ManuallyRemoveCharacterCheckerResult::Substitute) {
					file_has_substitute_chars_to_be_manually_removed = true;
				}
				else
				{
					if (!g_process_damaged_crlf)
					{
						print_validation_failure(filepath,
							"file contains disallowed character 0x{:02X}: line {}",
							static_cast<unsigned int>(ch),
							current_line);
						if (g_fix_disallowed_chars)
						{
							ShellExecutePath(filepath.c_str());
						}

						++disallowed_character_count;
						if (disallowed_character_count > 10)
						{
							print_validation_failure(filepath,
								"file contains more than 10 disallowed characters, stopping further reporting.");
							return;
						}
					}
				}
			}
		}
	}

	if (previous_ch == CR) { // file ends with CR
		file_has_single_cr = true;
	}

	if (!g_process_disallowed_chars)
	{
		if (file_has_single_cr) {
			print_validation_failure(filepath, "file contains CR line endings (possibly damaged CRLF).");
			if (g_fix_file_damaged_crlf)
			{
				if (ShouldAutomaticallyFixFile(filepath))
				{
					FixCrlfInFile(filepath);
				}
				// ShellExecutePath(filepath.c_str());
			}
		}
		else if (file_has_single_lf && file_has_crlf) {
			print_validation_failure(filepath, "file contains mixed line endings (both LF and CRLF).");
			if (g_fix_file_damaged_crlf)
			{
				if (ShouldAutomaticallyFixFile(filepath))
				{
					FixCrlfInFile(filepath);
				}
				// ShellExecutePath(filepath.c_str());
			}
		}
		/*
		else if (has_lf) {
			validation_failure(filepath, "file contains LF line endings.");

			if (previous != LF) {
				validation_failure(filepath, "file doesn't end with a newline.");
			}
		}
		else if (has_crlf) {
			if (previous2 != CR || previous != LF) {
				validation_failure(filepath, "file doesn't end with a newline.");
			}
		}
		*/
	}
}

// allow users to override parsing files with no extension
static void PrintHelp() noexcept
{
	println("Usage: ValidateLineEndings.exe");
	println(" - Scans all files in the current directory and its subdirectories for invalid characters");
	println(" - Skips known directories, file extensions, and filenames");
	println(" - Logs files with characters that need to be removed manually to validation_failures.log");
	println();
	println("optional parameters [specify only a single parameter]:");
	println("  -h | --help : prints this help message");
	println("  -print-skipped-files : print the list of skipped files and extensions to the console");
	println("  -fix-form-feed : removes the form-feed character from all source files");
	println("  -fix-substitute : removes the substitute character from all source files");
	println("  -fix-damaged-crlf : will automatically fix each file with a damaged CRLF");
	println("                      will prompt to allow fixing each file extension");
	println("  -fix-disallowed-chars : will ShellExecute each file with disallowed characters to be fixed");
	println("  -process-damaged-crlf : only report files that have damaged CRLF line endings");
	println("  -process-disallowed-chars : only report files that have disallowed characters");
}
int __cdecl main(int argc, char** argv) {
	g_log_file.open(g_log_filename_formatted, std::ios::out | std::ios::app);
	if (!g_log_file.is_open())
	{
		println("Failed to open log file {}", filesystem::path{ g_log_filename_formatted }.string());
		return 1;
	}

	if (argc == 2)
	{
		string_view arg = argv[1];

		// process terminating arguments first
		if (arg == "-?" || arg == "-h" || arg == "--help")
		{
			PrintHelp();
			return 0;
		}

		if (arg == "-print-skipped-files")
		{
			println("\nSkipped directories:");
			for (const auto& dir : skipped_directories)
			{
				print("{} ", filesystem::path{ dir }.string());
			}
			println("\n\nSkipped extensions:");
			for (const auto& ext : skipped_extensions)
			{
				print("{} ", filesystem::path{ ext }.string());
			}
			println("\n\nSkipped filenames:");
			for (const auto& name : skipped_filenames)
			{
				print("{} ", filesystem::path{ name }.string());
			}
			println("\n\nSkipped paths:");
			for (const auto& path : skipped_paths)
			{
				print("{} ", filesystem::path{ path }.string());
			}
			println("\n\nSkipped path prefixes:");
			for (const auto& prefix : skipped_path_prefixes)
			{
				print("{} ", filesystem::path{ prefix }.string());
			}
			println("");
			return 0;
		}

		if (arg == "-fix-form-feed")
		{
			g_fix_form_feed_chars = true;
		}
		else if (arg == "-fix-substitute")
		{
			g_fix_substitute_chars = true;
		}
		else if (arg == "-process-damaged-crlf")
		{
			g_process_damaged_crlf = true;
		}
		else if (arg == "-process-disallowed-chars")
		{
			g_process_disallowed_chars = true;
		}
		else if (arg == "-fix-damaged-crlf")
		{
			g_process_damaged_crlf = true;
			g_fix_file_damaged_crlf = true;
		}
		else if (arg == "-fix-disallowed-chars")
		{
			g_process_disallowed_chars = true;
			g_fix_disallowed_chars = true;
		}
		else
		{
			println(stderr, "Unknown argument: {}", arg);
			PrintHelp();
			return 1;
		}
	}
	else if (argc > 2)
	{
		string_view arg = argv[2];
		println(stderr, "Unknown argument: {}", arg);
		PrintHelp();
		return 1;
	}

	int files_scanned = 0;
	vector<uint8_t> buffer;
	for (filesystem::recursive_directory_iterator rdi{ "." }, last; rdi != last; ++rdi) {
		const filesystem::path& filepath = rdi->path();

		if (filepath == g_log_filename_formatted) {
			continue;
		}

		// must flatten all strings to lowercase for case-insensitive comparison
		// if there are non-ascii characters, will require case-sensitive strings in our lists
		wstring parent_path = filepath.parent_path().wstring();
		for (auto& ch : parent_path) {
			if (iswascii(ch)) {
				ch = towlower(ch);
			}
		}
		if (ranges::binary_search(skipped_paths, parent_path)) {
			continue;
		}

		bool prefix_matched = false;
		for (const auto& prefix : skipped_path_prefixes)
		{
			if (parent_path.starts_with(prefix)) {
				prefix_matched = true;
				break;
			}
		}
		if (prefix_matched) {
			continue;
		}

		// must flatten all strings to lowercase for case-insensitive comparison
		// if there are non-ascii characters, will require case-sensitive strings in our lists
		wstring filename = filepath.filename().wstring();
		for (auto& ch : filename) {
			if (iswascii(ch)) {
				ch = towlower(ch);
			}
		}
		if (ranges::binary_search(skipped_filenames, filename)) {
			continue;
		}

		if (!rdi->is_regular_file()) {
			if (rdi->is_directory()) {
				if (ranges::binary_search(skipped_directories, filename)) {
					rdi.disable_recursion_pending();
				}
			}
			continue;
		}

		auto extension = filepath.extension().wstring();
		for (auto& ch : extension) {
			if (iswascii(ch)) {
				ch = towlower(ch);
			}
		}
		if (ranges::binary_search(skipped_extensions, extension)) {
			continue;
		}

		// separately skipping .log files, as needed
		if (extension == L".log") {
			continue; // skip .log files
		}

		if (g_fix_form_feed_chars)
		{
			if (ranges::binary_search(extensions_to_fix_separately, extension))
			{
				RemoveCharInFile(filepath, FORM_FEED_CHARACTER);
				++files_scanned;
			}
		}
		else if (g_fix_substitute_chars)
		{
			if (ranges::binary_search(extensions_to_fix_separately, extension))
			{
				RemoveCharInFile(filepath, SUBSTITUTION_CHARACTER);
				++files_scanned;
			}
		}
		else
		{
			scan_file(filepath, buffer);
			++files_scanned;
		}
	}

	println(stdout, "Successfully scanned {} files.", files_scanned);

	if (!g_fix_form_feed_chars)
	{
		println(stdout, " - Found {} files that have invalid characters that must be resolved.", g_validation_failure_count.load());
		println(stdout, " - Logged to file {} files that are UTF16 that may need to be reviewed.", g_validation_logged_count.load());
		println(stdout,
			" - Found {} files that require separate fixes - see the log file for details.\n"
			"   Use the -fix-form-feed and -fix-substitute command line arguments to automatically fix these\n",
			g_validation_manual_update_count.load());
		return g_validation_failure_count;
	}

	return 0;
}
