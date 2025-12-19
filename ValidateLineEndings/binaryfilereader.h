#pragma once
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <print>
#include <vector>

class BinaryFileReader {
public:
	explicit BinaryFileReader(const std::filesystem::path& filepath) {
		const auto err = _wfopen_s(&m_file, filepath.c_str(), L"rb");

		if (err != 0 || !m_file) {
			std::println(stderr, "Validation failed: {} couldn't be opened.", filepath.string());
		}
	}

	[[nodiscard]] bool read_next_block(std::vector<unsigned char>& buffer) const
	{
		constexpr size_t BlockSize = 65536;
		buffer.resize(BlockSize);

		const size_t bytes_read = fread(buffer.data(), 1, BlockSize, m_file);
		buffer.resize(bytes_read);
		return !buffer.empty();
	}

	~BinaryFileReader() {
		if (m_file && fclose(m_file) != 0) {
			std::println(stderr, "fclose() failed.");
			abort();
		}
	}

	BinaryFileReader(const BinaryFileReader&) = delete;
	BinaryFileReader& operator=(const BinaryFileReader&) = delete;
	BinaryFileReader(BinaryFileReader&&) = delete;
	BinaryFileReader& operator=(BinaryFileReader&&) = delete;

private:
	FILE* m_file{ nullptr };
};
