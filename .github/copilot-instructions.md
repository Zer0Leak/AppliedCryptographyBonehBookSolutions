# GitHub Copilot Instructions

## C++ Code Guidelines

When generating or suggesting C++ code for this repository, always use **modern C++23** standards and features.

### Required C++ Standard
- Use C++23 as the minimum standard
- All projects in this repository are configured with `CXX_STANDARD 23`

### Preferred C++23 Features
- Use `std::print` and `std::println` instead of `std::cout` with `<<` operators
- Use `std::format` for string formatting
- Use `std::span` for array/buffer views
- Use `std::ranges` and `std::views` for data transformations
- Use `std::ranges::to<>` for range-to-container conversions
- Use `std::expected` for error handling where appropriate
- Use `std::optional` for optional values
- Use structured bindings (`auto [a, b] = ...`)
- Use trailing return type syntax (`auto func() -> ReturnType`)
- Use `[[nodiscard]]`, `[[maybe_unused]]`, and other attributes appropriately
- Use `constexpr` and `consteval` where possible
- Use concepts and requires clauses for template constraints

### Code Style
- Prefer `auto` for type deduction when the type is obvious
- Use `nullptr` instead of `NULL` or `0`
- Use scoped enums (`enum class`) instead of unscoped enums
- Use `using` aliases instead of `typedef`
- Prefer range-based for loops
- Use RAII for resource management
- Avoid raw pointers; prefer smart pointers (`std::unique_ptr`, `std::shared_ptr`)

### Example of Modern C++23 Style
```cpp
#include <print>
#include <span>
#include <vector>
#include <ranges>

[[nodiscard]] auto process_data(std::span<const int> data) -> std::vector<int> {
    return data 
        | std::views::filter([](int x) { return x > 0; })
        | std::views::transform([](int x) { return x * 2; })
        | std::ranges::to<std::vector>();
}

auto main() -> int {
    std::vector<int> numbers{1, -2, 3, -4, 5};
    auto result = process_data(numbers);
    std::println("Result size: {}", result.size());
    return 0;
}
```
