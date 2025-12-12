#pragma once

#include <array>
#include <bit> // std::to_integer
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace fasthex {

// ======================= LUTs =======================

// hex char → 0..15 (0xFF = invalid)
inline constexpr std::array<std::uint8_t, 256> make_decode_lut() {
    std::array<std::uint8_t, 256> t{};
    t.fill(0xFF);

    for (unsigned c = '0'; c <= '9'; ++c)
        t[c] = static_cast<std::uint8_t>(c - '0');
    for (unsigned c = 'a'; c <= 'f'; ++c)
        t[c] = static_cast<std::uint8_t>(c - 'a' + 10);
    for (unsigned c = 'A'; c <= 'F'; ++c)
        t[c] = static_cast<std::uint8_t>(c - 'A' + 10);

    return t;
}

// 0..15 → hex char
inline constexpr std::array<char, 16> ENCODE_LUT = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

inline constexpr auto DECODE_LUT = make_decode_lut();

// ======================= Output Traits =======================
// Provides: make(n_bytes) and data(out) as unsigned char*
//
// Extend by specializing fasthex::out_traits<YourType>.
template <class Out> struct out_traits;

template <> struct out_traits<std::string> {
    static std::string make(std::size_t n) { return std::string(n, '\0'); }
    static unsigned char *data(std::string &s) { return reinterpret_cast<unsigned char *>(s.data()); }
};

template <> struct out_traits<std::vector<std::uint8_t>> {
    static std::vector<std::uint8_t> make(std::size_t n) { return std::vector<std::uint8_t>(n); }
    static unsigned char *data(std::vector<std::uint8_t> &v) { return reinterpret_cast<unsigned char *>(v.data()); }
};

template <> struct out_traits<std::vector<std::byte>> {
    static std::vector<std::byte> make(std::size_t n) { return std::vector<std::byte>(n); }
    static unsigned char *data(std::vector<std::byte> &v) { return reinterpret_cast<unsigned char *>(v.data()); }
};

// Concept-like helper (kept simple for copy/paste)
template <class Out>
inline constexpr bool supported_out_v =
    std::is_same_v<Out, std::string> || std::is_same_v<Out, std::vector<std::uint8_t>> ||
    std::is_same_v<Out, std::vector<std::byte>>;

// ======================= Small helpers =======================

inline constexpr std::string_view as_string_view(std::string_view s) noexcept { return s; }
inline std::string_view as_string_view(const std::string &s) noexcept { return std::string_view{s}; }
inline std::string_view as_string_view(std::span<const char> s) noexcept { return {s.data(), s.size()}; }
inline std::string_view as_string_view(std::span<char> s) noexcept { return {s.data(), s.size()}; }

// ======================= Primitives =======================

// byte → 2 hex chars (no branches)
inline void byte_to_hex(std::byte byte, char *s) noexcept {
    const std::uint8_t b = std::to_integer<std::uint8_t>(byte);
    s[0] = ENCODE_LUT[b >> 4];
    s[1] = ENCODE_LUT[b & 0x0F];
}

// ======================= Bytes → Hex (encode) =======================

// Encode bytes from string_view (binary-safe) → hex string
inline std::string bytes_to_hex(std::string_view bytes) {
    const std::size_t n = bytes.size();
    std::string out;
    out.resize(n * 2);

    const auto *src = reinterpret_cast<const std::uint8_t *>(bytes.data());
    char *dst = out.data();

    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t b = src[i];
        dst[2 * i] = ENCODE_LUT[b >> 4];
        dst[2 * i + 1] = ENCODE_LUT[b & 0x0F];
    }
    return out;
}

// ---------- Bytes → string (binary-safe) ----------
inline std::string bytes_to_string(std::span<const std::byte> bytes) {
    return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

// Encode bytes from span<uint8_t> → hex string
inline std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    const std::size_t n = bytes.size();
    std::string out;
    out.resize(n * 2);

    const auto *src = bytes.data();
    char *dst = out.data();

    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t b = src[i];
        dst[2 * i] = ENCODE_LUT[b >> 4];
        dst[2 * i + 1] = ENCODE_LUT[b & 0x0F];
    }
    return out;
}

// Encode bytes from span<byte> → hex string
inline std::string bytes_to_hex(std::span<const std::byte> bytes) {
    const std::size_t n = bytes.size();
    std::string out;
    out.resize(n * 2);

    const auto *src = reinterpret_cast<const std::uint8_t *>(bytes.data());
    char *dst = out.data();

    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t b = src[i];
        dst[2 * i] = ENCODE_LUT[b >> 4];
        dst[2 * i + 1] = ENCODE_LUT[b & 0x0F];
    }
    return out;
}

// ======================= Hex → Bytes (decode) =======================

// Core (string_view) — Unchecked: assumes even length + valid hex. Fastest.
template <class Out> inline Out hex_to_bytes_unchecked(std::string_view hex) {
    static_assert(
        supported_out_v<Out>,
        "Out must be std::string or std::vector<uint8_t> or std::vector<std::byte> (extend out_traits to add more).");

    const std::size_t n = hex.size();
    Out out = out_traits<Out>::make(n / 2);

    const auto *in = reinterpret_cast<const unsigned char *>(hex.data());
    auto *dst = out_traits<Out>::data(out);

    for (std::size_t i = 0, j = 0; i < n; i += 2, ++j) {
        dst[j] = static_cast<unsigned char>((DECODE_LUT[in[i]] << 4) | DECODE_LUT[in[i + 1]]);
    }
    return out;
}

// Overloads for hex input types (unchecked)
template <class Out> inline Out hex_to_bytes_unchecked(const std::string &hex) {
    return hex_to_bytes_unchecked<Out>(as_string_view(hex));
}
template <class Out> inline Out hex_to_bytes_unchecked(std::span<const char> hex) {
    return hex_to_bytes_unchecked<Out>(as_string_view(hex));
}
template <class Out> inline Out hex_to_bytes_unchecked(std::span<char> hex) {
    return hex_to_bytes_unchecked<Out>(as_string_view(hex));
}

// Core (string_view) — Checked: validates even length + valid chars.
template <class Out> inline std::optional<Out> hex_to_bytes(std::string_view hex) {
    static_assert(
        supported_out_v<Out>,
        "Out must be std::string or std::vector<uint8_t> or std::vector<std::byte> (extend out_traits to add more).");

    const std::size_t n = hex.size();
    if (n & 1)
        return std::nullopt;

    Out out = out_traits<Out>::make(n / 2);

    const auto *in = reinterpret_cast<const unsigned char *>(hex.data());
    auto *dst = out_traits<Out>::data(out);

    for (std::size_t i = 0, j = 0; i < n; i += 2, ++j) {
        const std::uint8_t hi = DECODE_LUT[in[i]];
        const std::uint8_t lo = DECODE_LUT[in[i + 1]];
        if ((hi | lo) == 0xFF)
            return std::nullopt;
        dst[j] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

// Overloads for hex input types (checked)
template <class Out> inline std::optional<Out> hex_to_bytes(const std::string &hex) {
    return hex_to_bytes<Out>(as_string_view(hex));
}
template <class Out> inline std::optional<Out> hex_to_bytes(std::span<const char> hex) {
    return hex_to_bytes<Out>(as_string_view(hex));
}
template <class Out> inline std::optional<Out> hex_to_bytes(std::span<char> hex) {
    return hex_to_bytes<Out>(as_string_view(hex));
}

// ======================= Convenience Names =======================

inline std::string hex_to_string_unchecked(std::string_view hex) { return hex_to_bytes_unchecked<std::string>(hex); }
inline std::optional<std::string> hex_to_string(std::string_view hex) { return hex_to_bytes<std::string>(hex); }

inline std::vector<std::uint8_t> hex_to_u8_unchecked(std::string_view hex) {
    return hex_to_bytes_unchecked<std::vector<std::uint8_t>>(hex);
}
inline std::optional<std::vector<std::uint8_t>> hex_to_u8(std::string_view hex) {
    return hex_to_bytes<std::vector<std::uint8_t>>(hex);
}

} // namespace fasthex
