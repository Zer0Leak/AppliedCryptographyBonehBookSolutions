#pragma once

#include <format>
#include <print>
#include <source_location>
#include <string_view>

// Usage example:
// log(log_level::error, {}, "file_size failed for '{}': {}", file, ec.message());

enum class log_level { debug, info, warn, error };

inline constexpr log_level min_log_level = log_level::debug;

template <typename... Args>
auto log(log_level level, std::source_location loc = std::source_location::current(),
         std::format_string<Args...> fmt = "", Args &&...args) -> void {
    if (level < min_log_level)
        return;

    constexpr auto level_str = [](log_level lvl) constexpr -> std::string_view {
        switch (lvl) {
        case log_level::debug:
            return "DEBUG";
        case log_level::info:
            return "INFO";
        case log_level::warn:
            return "WARN";
        case log_level::error:
            return "ERROR";
        }
        return "UNKNOWN";
    };

    std::println(stderr, "[{}] {}:{} - {}", level_str(level), loc.file_name(), loc.line(),
                 std::format(fmt, std::forward<Args>(args)...));
}
