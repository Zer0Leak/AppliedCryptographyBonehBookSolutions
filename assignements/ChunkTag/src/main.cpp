#include "log.hpp"

#include <array>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <ostream>
#include <span>
#include <string_view>
#include <sys/types.h>
#include <system_error>
#include <utility>

static constexpr ssize_t BLOCK_SIZE = 1024;
static constexpr ssize_t TAG_SIZE = 256 / 8;

auto open_for_reading(std::string_view file) -> std::optional<std::pair<std::ifstream, std::uintmax_t>> {
    std::error_code ec;
    const auto size = std::filesystem::file_size(file, ec);
    if (ec) [[unlikely]] {
        log(log_level::error, {}, "file_size failed for '{}': {}", file, ec.message());
        return std::nullopt;
    }

    std::ifstream in(file.data(), std::ios::binary);
    if (!in) [[unlikely]] {
        log(log_level::error, {}, "cannot open file '{}' for reading", file);
        return std::nullopt;
    }

    log(log_level::debug, {}, "opened file '{}', size={}", file, size);
    return std::pair{std::move(in), size}; // position at end - (size % 1024)
}

auto hash_block(std::span<std::byte> block, std::span<std::byte> output_tag) -> std::span<std::byte> {
    CryptoPP::SHA256 hash;
    hash.Update(reinterpret_cast<const CryptoPP::byte *>(block.data()), block.size());
    hash.Final(reinterpret_cast<CryptoPP::byte *>(output_tag.data()));
    return output_tag;
}

auto seek_and_read(std::ifstream &in, std::ios::seekdir dir, const size_t read_size, const size_t offset,
                   std::span<std::byte> buffer, const std::string_view file_path) -> bool {
    in.seekg(offset, dir);
    if (!in) [[unlikely]] {
        log(log_level::error, {}, "seek failed for file '{}'", file_path);
        return false;
    }

    if (!in.read(reinterpret_cast<char *>(buffer.data()), read_size)) {
        log(log_level::error, {}, "read failed for file '{}'", file_path);
        return false;
    }

    return true;
}

auto bytes_to_string(std::span<std::byte> bytes) -> std::string {
    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output), false);
    encoder.Put(reinterpret_cast<const CryptoPP::byte *>(bytes.data()), bytes.size());
    encoder.MessageEnd();
    return output;
}

auto calculate_chunk_tag(std::ifstream &in, const std::string_view file_path,
                         const std::size_t file_size) -> std::optional<std::array<std::byte, TAG_SIZE>> {
    size_t offset = file_size % BLOCK_SIZE;
    constexpr size_t buffer_size = BLOCK_SIZE + TAG_SIZE;
    std::array<std::byte, buffer_size> buffer;
    auto remaning_size = file_size;
    size_t read_size = offset;

    if (!seek_and_read(in, std::ios::end, read_size, -offset, buffer, file_path)) {
        return std::nullopt;
    }

    auto chunk = std::span<std::byte>(buffer.data(), read_size);
    remaning_size -= read_size;
    auto tag = hash_block(chunk, std::span<std::byte>(buffer.data() + BLOCK_SIZE, TAG_SIZE));

    offset = read_size + BLOCK_SIZE;
    read_size = BLOCK_SIZE;
    chunk = std::span<std::byte>(buffer.data(), read_size + TAG_SIZE);
    while (remaning_size >= read_size) {
        if (!seek_and_read(in, std::ios::cur, read_size, -offset, buffer, file_path)) {
            return std::nullopt;
        }
        remaning_size -= read_size;
        offset = read_size + BLOCK_SIZE;

        tag = hash_block(chunk, tag);
    }

    std::array<std::byte, TAG_SIZE> result_tag;
    std::copy_n(tag.data(), TAG_SIZE, result_tag.data());

    return result_tag;
}

auto main() -> int {
    // constexpr std::string_view file_path = "/tmp/6.2.birthday.mp4_download"; // test
    // 03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8
    constexpr std::string_view file_path = "/tmp/6.1.intro.mp4_download";

    log(log_level::info, {}, "starting application");

    auto result = open_for_reading(file_path);
    if (!result) [[unlikely]]
        return 1;

    auto &[file_stream, file_size] = *result;
    log(log_level::info, {}, "file opened successfully, size: {}", file_size);

    auto tag = calculate_chunk_tag(file_stream, file_path, file_size);
    if (!tag) [[unlikely]]
        return 1;

    std::println("ChunkTag: {}", bytes_to_string(*tag));

    return 0;
}
