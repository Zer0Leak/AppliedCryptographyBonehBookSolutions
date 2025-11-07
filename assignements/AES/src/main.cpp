#include <format>
#include <iostream>

int main(int argc, char *argv[]) {
    auto s=std::format("{}",42);
    std::cout << s << std::endl;
    return 0;
}
