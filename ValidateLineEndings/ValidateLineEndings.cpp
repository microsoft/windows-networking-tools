#include <algorithm>
#include <cctype>
#include <cstdio>
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

bool g_only_fix_form_feed_chars = false;
bool g_only_process_damaged_crlf = false;
bool g_only_process_disallowed_chars = false;

bool g_fix_file_damaged_crlf = false;
bool g_open_file_disallowed_chars = false;

std::vector<std::wstring> g_allowed_file_extensions_for_fixing_disallowed_chars;
std::vector<std::wstring> g_blocked_file_extensions_for_fixing_disallowed_chars;

constexpr auto* g_log_filename = L"validation_failures.log";
constexpr auto* g_log_filename_formatted = L".\\validation_failures.log";
static ofstream g_log_file(g_log_filename);

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
		printf(" - skipping the file (%ws) from fixing disallowed characters.\n", filepath.c_str());
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
	printf(" * Should files with the extension (%ws) be allowed to automatically be fixed? (y/n) ",
		filepath.extension().c_str());
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
		printf(" - skipping the file for fixing disallowed characters.\n");
		return false;
	}
}
void ShellExecutePath(_In_ PCWSTR path) noexcept
{
	SHELLEXECUTEINFOW shellexec{};
	shellexec.cbSize = sizeof(SHELLEXECUTEINFOW);
	shellexec.lpVerb = L"open";
	shellexec.lpFile = path;
	shellexec.nShow = SW_SHOWNORMAL;
	if (!ShellExecuteExW(&shellexec))
	{
		const auto gle = GetLastError();
		printf("ShellExecuteEx failed - gle 0x%x ShellError 0x%p\n", gle, shellexec.hInstApp);
	}
	else
	{
		printf("Hit Enter key after fixing the files .. ");
		std::string str;
		std::getline(std::cin, str);
		printf(" .. resuming\n");
	}
}

constexpr uint8_t FORM_FEED = 0x0C;
constexpr uint8_t CR = 0x0D; // '\r'
constexpr uint8_t LF = 0x0A; // '\n'

void FixCrlfInFile(const filesystem::path& filepath)
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
		for (auto iter = buffer.cbegin(); iter != buffer.cend(); ++iter)
		{
			const auto current_character = *iter;

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

	printf("Replacing %ws\n", filepath.c_str());
	if (!MoveFileEx(temp_filename, filepath.c_str(), MOVEFILE_REPLACE_EXISTING))
	{
		const auto gle = GetLastError();
		printf("Failed MoveFileEx(%ws, %ws) : %d", temp_filename, filepath.c_str(), gle);
		return;
	}
	DeleteFile(temp_filename);
}
void RemoveCharInFile(const filesystem::path& filepath, uint8_t char_to_remove)
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

	bool file_fixed = false;
	bool bom_checked = false;
	for (BinaryFileReader binary_file{ filepath }; binary_file.read_next_block(buffer);) {
		if (!bom_checked)
		{
			if (Utf16Checker::Utf16Bom(buffer) != Utf16Checker::BomType::None)
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
		printf("Replacing %ws\n", filepath.c_str());
		if (!MoveFileEx(temp_filename, filepath.c_str(), MOVEFILE_REPLACE_EXISTING))
		{
			const auto gle = GetLastError();
			printf("Failed MoveFileEx(%ws, %ws) : %d", temp_filename, filepath.c_str(), gle);
			return;
		}
	}

	DeleteFile(temp_filename);
}

static void scan_file(const filesystem::path& filepath, vector<uint8_t>& buffer)
{
	bool file_has_single_cr = false;
	bool file_has_single_lf = false;
	bool file_has_crlf = false;

	bool file_has_chars_to_be_manually_removed = false;
	const auto log_manual_remove_chars_at_exit = wil::scope_exit([&]() {
		if (!g_only_process_damaged_crlf && !g_only_process_disallowed_chars)
		{
			if (file_has_chars_to_be_manually_removed) {
				log_validation_failure(filepath, "file contains the 0x0C character that need to be removed.");
			}
		}
		});

	size_t file_offset = 0;
	size_t current_line = 1;
	size_t disallowed_character_count = 0;
	Utf8Checker utf8_checker;
	uint8_t previous_ch = '\0';
	bool has_utf8_bom = false;
	bool bom_checked = false;
	for (BinaryFileReader binary_file{ filepath }; binary_file.read_next_block(buffer);) {
		if (!bom_checked)
		{
			has_utf8_bom = Utf8Checker::HasUtf8Bom(buffer);
			switch (Utf16Checker::Utf16Bom(buffer))
			{
			case Utf16Checker::BomType::UTF16_LE:
				if (filepath.has_extension() &&
					(filepath.extension() == L".idl"))
				{
					// skip logging for .idl files
				}
				else
				{
					log_validation_failure(filepath, "file contains UTF-16 LE BOM - skipping");
				}
				return;
			case Utf16Checker::BomType::UTF16_BE:
				if (filepath.has_extension() &&
					(filepath.extension() == L".idl"))
				{
					// skip logging for .idl files
				}
				else
				{
					log_validation_failure(filepath, "file contains UTF-16 BE BOM - skipping");
				}
				return;
			}
			bom_checked = true;
		}

		for (const auto& ch : buffer) {
			++file_offset;
			if (file_offset <= 3 && has_utf8_bom) {
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
				if (Utf8Checker::IsCharToManuallyRemove(ch)) {
					file_has_chars_to_be_manually_removed = true;
				}
				else
				{
					if (!g_only_process_damaged_crlf)
					{
						print_validation_failure(filepath,
							"file contains disallowed character 0x{:02X}: line {}",
							static_cast<unsigned int>(ch),
							current_line);
						if (g_open_file_disallowed_chars)
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

	if (!g_only_process_disallowed_chars)
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
void PrintHelp() noexcept
{
	println("Usage: ValidateLineEndings.exe");
	println(" - Scans all files in the current directory and its subdirectories for invalid characters");
	println(" - Skips known directories, file extensions, and filenames");
	println(" - Logs files with characters that need to be removed manually to validation_failures.log");
	println();
	println("optional parameters [specify only a single parameter]:");
	println("  -h | --help : prints this help message");
	println("  -fix-form-feed: removes the form-feed character from all source files");
	println("  -print-skipped-files : print the list of skipped files and extensions to the console");
	println("  -only-process-damaged-crlf : only report files that have damaged CRLF line endings");
	println("  -only-process-disallowed-chars : only report files that have disallowed characters");
	println("  -fix-file-damaged-crlf : will automatically fix each file with a damaged CRLF");
	println("							will prompt to allow each unique file extension");
	println("  -open-file-disallowed-chars : will ShellExecute each file with disallowed characters to be fixed");
}
int main(int argc, char** argv) {
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
				printf("%ls ", dir.data());
			}
			println("\n\nSkipped extensions:");
			for (const auto& ext : skipped_extensions)
			{
				printf("%ls ", ext.data());
			}
			println("\n\nSkipped filenames:");
			for (const auto& fname : skipped_filenames)
			{
				printf("%ls ", fname.data());
			}
			println("\n\nSkipped paths:");
			for (const auto& p : skipped_paths)
			{
				printf("%ls ", p.data());
			}
			printf("\n");
			return 0;
		}

		if (arg == "-fix-form-feed")
		{
			g_only_fix_form_feed_chars = true;
		}
		else if (arg == "-only-process-damaged-crlf")
		{
			g_only_process_damaged_crlf = true;
		}
		else if (arg == "-only-process-disallowed-chars")
		{
			g_only_process_disallowed_chars = true;
		}
		else if (arg == "-fix-file-damaged-crlf")
		{
			g_only_process_damaged_crlf = true;
			g_fix_file_damaged_crlf = true;
		}
		else if (arg == "-open-file-disallowed-chars")
		{
			g_only_process_disallowed_chars = true;
			g_open_file_disallowed_chars = true;
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

	if (!g_log_file.is_open()) {
		println(stderr, "Failed to open log file for writing.");
		return 1;
	}

	int files_scanned = 0;
	vector<uint8_t> buffer;
	for (filesystem::recursive_directory_iterator rdi{ "." }, last; rdi != last; ++rdi) {
		const filesystem::path& filepath = rdi->path();

		if (filepath == g_log_filename_formatted) {
			continue;
		}
		if (ranges::binary_search(skipped_paths, filepath.parent_path())) {
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

		if (g_only_fix_form_feed_chars)
		{
			if (ranges::binary_search(extensions_to_fix_form_feed, extension))
			{
				RemoveCharInFile(filepath, FORM_FEED);
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

	if (!g_only_fix_form_feed_chars)
	{
		println(stdout, " - Found {} files that have invalid characters that must be resolved.", g_validation_failure_count.load());
		println(stdout, " - Logged to file {} files that have flagged characters to be removed.", g_validation_logged_count.load());
		return g_validation_failure_count;
	}

	return 0;
}
