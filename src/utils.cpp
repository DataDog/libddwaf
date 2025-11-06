// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace ddwaf {

std::vector<std::string_view> split(std::string_view str, char sep)
{
    std::vector<std::string_view> components;

    std::size_t start = 0;
    while (start < str.size()) {
        const std::size_t end = str.find(sep, start);

        if (end == start) {
            // Ignore zero-sized strings
            start = end + 1;
            continue;
        }

        if (end == std::string_view::npos) {
            // Last element
            components.emplace_back(str.substr(start));
            start = str.size();
        } else {
            components.emplace_back(str.substr(start, end - start));
            start = end + 1;
        }
    }

    return components;
}

std::vector<std::variant<std::string_view, int64_t>> convert_key_path(
    std::span<const std::variant<std::string, int64_t>> key_path)
{
    std::vector<std::variant<std::string_view, int64_t>> result;
    result.reserve(key_path.size());

    for (const auto &key : key_path) {
        std::visit([&result](auto &&k) { result.emplace_back(k); }, key);
    }
    return result;
}

bool string_iequals(std::string_view left, std::string_view right)
{
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin(),
               [](char l, char r) { return tolower(l) == tolower(r); });
}

template <typename T> std::string to_string(T value) { return ddwaf::fmt::format("{}", value); }

template std::string to_string<bool>(bool value);
template std::string to_string<int64_t>(int64_t value);
template std::string to_string<uint64_t>(uint64_t value);
template std::string to_string<unsigned>(unsigned value);
template std::string to_string<double>(double value);

} // namespace ddwaf
