#include <charconv>
#include <format>
#include <iostream>
#include <optional>
#include <print>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

using namespace std;
using namespace CryptoPP;

enum class AESMode { CBC, CTR };

// Converts a hex string to a byte vector
[[nodiscard]] auto hex_string_to_bytes(string_view hex_str) -> optional<vector<uint8_t>> {
    if (hex_str.length() % 2 != 0) {
        return nullopt;
    }

    vector<uint8_t> bytes;
    bytes.reserve(hex_str.length() / 2);

    for (size_t i = 0; i < hex_str.length(); i += 2) {
        uint8_t value;
        auto [ptr, ec] = std::from_chars(hex_str.data() + i, hex_str.data() + i + 2, value, 16);
        if (ec != std::errc{}) {
            return nullopt;
        }
        bytes.push_back(value);
    }

    return bytes;
}

// AES decryption supporting CBC and CTR modes
[[nodiscard]] auto decrypt_aes(const span<const uint8_t> ciphertext, const span<const uint8_t, 16> key,
                               AESMode mode) -> string {
    if (ciphertext.size() < 16) {
        throw invalid_argument("Ciphertext too short (missing IV)");
    }

    // Extract IV (first 16 bytes) and actual ciphertext
    auto iv = ciphertext.first<16>();
    auto encrypted_data = ciphertext.subspan(16);

    // CBC mode requires data to be multiple of 16 bytes, CTR mode doesn't
    if (mode == AESMode::CBC && encrypted_data.size() % 16 != 0) {
        throw invalid_argument("CBC mode: ciphertext length must be multiple of 16 bytes");
    }

    try {
        string decrypted;

        switch (mode) {
        case AESMode::CBC: {
            CBC_Mode<AES>::Decryption decryption;
            decryption.SetKeyWithIV(key.data(), key.size(), iv.data());

            StringSource source(encrypted_data.data(), encrypted_data.size(),
                                true, // pump all
                                new StreamTransformationFilter(decryption, new StringSink(decrypted),
                                                               StreamTransformationFilter::PKCS_PADDING));
            break;
        }
        case AESMode::CTR: {
            CTR_Mode<AES>::Decryption decryption;
            decryption.SetKeyWithIV(key.data(), key.size(), iv.data());

            StringSource source(encrypted_data.data(), encrypted_data.size(),
                                true, // pump all
                                new StreamTransformationFilter(decryption, new StringSink(decrypted),
                                                               StreamTransformationFilter::NO_PADDING));
            break;
        }
        default:
            throw invalid_argument("Unsupported AES mode");
        }

        return decrypted;
    } catch (const Exception &e) {
        throw runtime_error(format("Crypto++ decryption failed: {}", e.what()));
    }
}

// Decrypt AES with specified mode - prints result, throws on failure
auto decrypt_and_print(string_view key_hex, string_view cipher_hex, AESMode mode = AESMode::CBC) -> void {
    auto key_bytes = hex_string_to_bytes(key_hex);
    if (!key_bytes) {
        throw runtime_error("Error parsing key - invalid hex format");
    }

    auto cipher_bytes = hex_string_to_bytes(cipher_hex);
    if (!cipher_bytes) {
        throw runtime_error("Error parsing ciphertext - invalid hex format");
    }

    // Validate key length
    if (key_bytes->size() != 16) {
        throw runtime_error(format("Invalid key length: {} (expected 16 bytes)", key_bytes->size()));
    }

    // span for safe array access
    span<const uint8_t, 16> key_span{key_bytes->data(), 16};

    auto result = decrypt_aes(*cipher_bytes, key_span, mode);

    auto mode_name = (mode == AESMode::CBC) ? "CBC" : "CTR";
    println("Decrypted message ({}): |{}|", mode_name, result);
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
    constexpr string_view key1 = "140b41b22a29beb4061bda66b6747e14";
    constexpr string_view cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465"
                                    "d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";

    constexpr string_view key2 = "140b41b22a29beb4061bda66b6747e14";
    constexpr string_view cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac64"
                                    "6ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";

    constexpr string_view key3 = "36f18357be4dbd77f050515c73fcf9f2";
    constexpr string_view cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0ad"
                                    "b5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd"
                                    "9afa9329";

    constexpr string_view key4 = "36f18357be4dbd77f050515c73fcf9f2";
    constexpr string_view cipher4 =
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";

    try {
        decrypt_and_print(key1, cipher1);
        decrypt_and_print(key2, cipher2);
        decrypt_and_print(key3, cipher3, AESMode::CTR);
        decrypt_and_print(key4, cipher4, AESMode::CTR);
        return 0;
    } catch (const exception &e) {
        println(cerr, "Error: {}", e.what());
        return 1;
    }
}