# GitHub Copilot Instructions

## C++ Code Style

When generating C++ code for this repository, always use **modern C++23** features and idioms.

### Required Standards

- Use C++23 standard (the repository is configured with `CXX_STANDARD 23`)
- Prefer modern C++ features over legacy approaches

### Preferred C++23 Features

- Use `std::print` and `std::println` instead of `std::cout <<`
- Use `std::format` for string formatting
- Use `std::ranges` and `std::views` for range-based operations
- Use `std::ranges::to<>` for converting ranges to containers
- Use `std::views::zip` for iterating over multiple ranges simultaneously
- Use `std::expected` for error handling where appropriate
- Use `std::optional` for optional values
- Use `std::string_view` for non-owning string references
- Use `std::span` for non-owning array/container views
- Use structured bindings (`auto [a, b] = ...`)
- Use `[[nodiscard]]` attribute for functions whose return value should not be ignored
- Use `[[maybe_unused]]` for intentionally unused parameters
- Use `constexpr` and `consteval` where possible
- Use concepts and constraints for template parameters
- Use lambda expressions with appropriate captures
- Use `auto` for type inference where it improves readability
- Use range-based for loops
- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) instead of raw pointers for ownership
- Use `std::array` instead of C-style arrays
- Use `std::variant` and `std::visit` for type-safe unions
- Use `enum class` instead of plain enums

### Code Style

- Follow LLVM code style (as configured in project `.clang-format` files)
- Use 4 spaces for indentation
- Maximum line length of 120 characters
- Use `nullptr` instead of `NULL` or `0` for null pointers
- Prefer `using` over `typedef`
