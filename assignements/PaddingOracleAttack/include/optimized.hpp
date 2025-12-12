#pragma once

#include <cstring>
#include <type_traits>
#include <vector>

namespace optimized {

template <class T> void append_destroy_src(std::vector<T> &dst, std::vector<T> &src) {
    dst.reserve(dst.size() + src.size());

    if constexpr (std::is_trivially_copyable_v<T>) {
        const std::size_t old = dst.size();
        dst.resize(old + src.size());
        std::memcpy(dst.data() + old, src.data(), src.size() * sizeof(T));
        src.clear();
    } else {
        dst.insert(dst.end(), std::make_move_iterator(src.begin()), std::make_move_iterator(src.end()));
        src.clear();
    }
}

} // namespace optimized
