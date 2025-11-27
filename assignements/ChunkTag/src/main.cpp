#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string_view>

auto open_for_reading(std::string_view file) -> std::ifstream {
  const auto size = std::filesystem::file_size(file); // throws if missing
  std::ifstream in(file.data(), std::ios::binary);
  if (!in)
    throw std::runtime_error("cannot open file for reading");

  const auto backoff = static_cast<std::streamoff>(size % 1024);
  in.seekg(-backoff, std::ios::end);
  if (!in)
    throw std::runtime_error("seek failed");

  return in; // position at end - (size % 1024)
}

int main() {
  constexpr auto test_file_path = "~/Downloads/6.2.birthday.mp4_download";
  constexpr auto file_path = "~/Downloads/6.1.intro.mp4_download";

  auto file_if = open_for_reading(test_file_path);

  return 0;
}
