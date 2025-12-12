#include "fasthex.hpp"
#include "log.hpp"
#include "optimized.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <curl/curl.h>
#include <format>
#include <iterator>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <sys/types.h>

using namespace fasthex;
using namespace optimized;
using std::println;

namespace {

auto query_padding_oracle(std::string_view parameter) -> std::optional<long> {
    auto curl = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>{curl_easy_init(), &curl_easy_cleanup};
    if (!curl) {
        std::println(stderr, "Failed to initialize libcurl");
        return std::nullopt;
    }

    const auto url = std::format("http://crypto-class.appspot.com/po?er={}", parameter);
    std::string response_body;

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_NOBODY, 1L);

    if (const auto result = curl_easy_perform(curl.get()); result != CURLE_OK) {
        println(stderr, "HTTP request failed: {}", curl_easy_strerror(result));
        return std::nullopt;
    }

    long status_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);

    return status_code;
}

} // namespace

static int detect_last_block_padding_length(int block_size, std::string_view parameter) {
    for (int pad_len = block_size; pad_len > 0; --pad_len) {
        std::string modified_blocks = std::string(parameter);
        const auto pos = modified_blocks.size() / 2 - block_size - pad_len;
        const auto hex_pos = pos * 2;
        uint8_t c_byte = 0;
        std::from_chars(modified_blocks.data() + hex_pos, modified_blocks.data() + hex_pos + 2, c_byte, 16);
        c_byte ^= 0xFF;
        byte_to_hex(std::byte{c_byte}, modified_blocks.data() + hex_pos);
        auto status = query_padding_oracle(modified_blocks);
        if (status) {
            if (*status != 403) {
                // mal formed padding
                return pad_len;
            }
        }
    }
    throw std::runtime_error("Failed to detect padding length");
}

int main(int, char *[]) {
    constexpr auto block_size = 16;
    constexpr auto block_size_hex = block_size * 2;

    auto curlGlobal = std::unique_ptr<void, void (*)(void *)>{(curl_global_init(CURL_GLOBAL_DEFAULT), nullptr),
                                                              [](void *) { curl_global_cleanup(); }};

    const std::string hex_original_parameter = R"(f20bdba6ff29eed7b046d1df9fb70000)"
                                               R"(58b1ffb4210a580f748b4ac714c001bd)"
                                               R"(4a61044426fb515dad3f21f18aa577c0)"
                                               R"(bdf302936266926ff37dbf7035d5eeb4)";

    int num_blocks = (hex_original_parameter.size() / block_size_hex) - 1; // exclude initial iv
    auto know_blocks = 0;
    std::vector<std::byte> decrypted_blocks_bytes;

    know_blocks = 0;
    while (know_blocks < num_blocks) {
        std::string hex_parameter = hex_original_parameter;
        auto previous_block_hex_offset = (know_blocks * block_size_hex);
        std::vector<std::byte> current_decrypted_block_bytes(block_size, std::byte{0x0});
        std::span<char> previous_hex_block =
            std::span<char>(hex_parameter).subspan(previous_block_hex_offset, block_size_hex);
        auto original_previous_block_bytes = hex_to_bytes_unchecked<std::vector<std::byte>>(previous_hex_block);

        auto known_chars = 0;

        auto last_block_deteced_padding_length = 0;
        if (know_blocks == num_blocks - 1) {
            // TODO: last block special case. tot detect padding length first
            auto query_param =
                std::string_view(hex_parameter).substr(know_blocks * block_size_hex, block_size_hex + block_size_hex);
            // last_block_deteced_padding_length = detect_last_block_padding_length(block_size, hex_original_parameter);
            // last_block_deteced_padding_length = detect_last_block_padding_length(block_size, query_param);
            last_block_deteced_padding_length = 9;
        }
        while (known_chars < block_size) {
            if ((know_blocks == num_blocks - 1) && (known_chars < last_block_deteced_padding_length)) {
                for (auto i = 0; i < last_block_deteced_padding_length; ++i) {
                    std::println("know_chars: {} -> [0x{:02x}]", i, last_block_deteced_padding_length);
                }
                std::fflush(stdout);
                std::fill(current_decrypted_block_bytes.end() - last_block_deteced_padding_length,
                          current_decrypted_block_bytes.end(),
                          static_cast<std::byte>(last_block_deteced_padding_length));
                known_chars = last_block_deteced_padding_length;
            } else {
                std::print("know_chars: {} -> ", known_chars);
                std::fflush(stdout);
                const auto guess_pos = block_size - known_chars - 1;
                const auto guess_hex_pos = guess_pos * 2;

                auto pad = static_cast<std::byte>(known_chars + 1);
                for (auto i = 0; i < known_chars; ++i) {
                    const auto pos = block_size - 1 - i;
                    const auto hex_pos = pos * 2;
                    const std::byte c_byte = original_previous_block_bytes[pos];
                    const std::byte b_byte = current_decrypted_block_bytes[pos];
                    const std::byte replacing_byte = c_byte ^ b_byte ^ pad;
                    byte_to_hex(replacing_byte, previous_hex_block.data() + hex_pos);
                }

                uint8_t c_byte = 0;
                std::from_chars(previous_hex_block.data() + guess_hex_pos,
                                previous_hex_block.data() + guess_hex_pos + 2, c_byte, 16);
                bool byte_found = false;
                for (uint16_t guess = 0x00; guess <= 0xFF; ++guess) {
                    const auto replacing_byte =
                        static_cast<std::byte>(c_byte ^ static_cast<uint8_t>(guess) ^ std::to_integer<uint8_t>(pad));
                    byte_to_hex(replacing_byte, previous_hex_block.data() + guess_hex_pos);
                    // auto query_param = std::string_view(parameter).substr(0, know_blocks * block_size_hex +
                    // block_size_hex + block_size_hex); // known + previous + current
                    auto query_param = std::string_view(hex_parameter)
                                           .substr(know_blocks * block_size_hex, block_size_hex + block_size_hex);
                    if (const auto status = query_padding_oracle(query_param)) {
                        if (*status == 404) {
                            std::print("[0x{:x}]\n", guess);
                            std::fflush(stdout);
                            current_decrypted_block_bytes[guess_pos] = static_cast<std::byte>(guess);
                            byte_found = true;
                            break;
                        } else {
                            if (*status != 403) {
                                println(stderr, "Unexpected HTTP status code: {}", *status);
                                return 1;
                            } else {
                                if ((guess % 16) == 0) {
                                    std::print("0x{:x} ", guess);
                                    std::fflush(stdout);
                                }
                            }
                        }
                    }
                }
                // byte_to_hex(c_byte, parameter.data() + guess_pos); // restore original byte
                if (!byte_found) {
                    println();
                    println(stderr, "Failed to find byte {}, at position {}", known_chars + 1, guess_pos);
                    return 1;
                }
                ++known_chars;
            }
        }
        if (know_blocks == num_blocks - 1) {
            current_decrypted_block_bytes.resize(current_decrypted_block_bytes.size() -
                                                 last_block_deteced_padding_length);
        }
        println("");
        println("Recovered plaintext (hex): [{}]", bytes_to_hex(current_decrypted_block_bytes));
        println("Recovered plaintext (ASCII): [{}]", bytes_to_string(current_decrypted_block_bytes));

        append_destroy_src(decrypted_blocks_bytes, current_decrypted_block_bytes);
        ++know_blocks;
    }

    println("Recovered plaintext (hex): [{}]", bytes_to_hex(decrypted_blocks_bytes));
    println("Recovered plaintext (ASCII): [{}]", bytes_to_string(decrypted_blocks_bytes));

    return 0;
}
