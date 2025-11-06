// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <fmt/format.h>

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
// Convert numbers to strings
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
// (string, length), only for literals
#define STRL(value) value, sizeof(value) - 1
// NOLINTEND(cppcoreguidelines-macro-usage)

template <typename T> using optional_ref = std::optional<std::reference_wrapper<T>>;
using scalar_type = std::variant<bool, int64_t, uint64_t, double, std::string>;

namespace ddwaf {

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
inline bool isalpha(char c) { return (static_cast<unsigned>(c) | 32) - 'a' < 26; }
inline bool isdigit(char c) { return static_cast<unsigned>(c) - '0' < 10; }
inline bool isxdigit(char c) { return isdigit(c) || ((unsigned)c | 32) - 'a' < 6; }
inline bool isspace(char c)
{
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}
inline bool isupper(char c) { return static_cast<unsigned>(c) - 'A' < 26; }
inline bool islower(char c) { return static_cast<unsigned>(c) - 'a' < 26; }
inline bool isalnum(char c) { return isalpha(c) || isdigit(c); }
inline bool isboundary(char c) { return !isalnum(c) && c != '_'; }
inline char tolower(char c) { return isupper(c) ? static_cast<char>(c | 32) : c; }
inline uint8_t from_hex(char c)
{
    auto uc = static_cast<uint8_t>(c);
    return isdigit(c) ? (uc - '0') : ((uc | 32) - 'a' + 0xa);
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

template <class Fn> class defer {
public:
    explicit defer(Fn &&fn) noexcept : fn_(std::move(fn)) {}
    ~defer() { fn_(); }

    defer(const defer &) = delete;
    defer(defer &&) = delete;
    defer &operator=(const defer &) = delete;
    defer &operator=(defer &&) = delete;

protected:
    Fn fn_;
};

template <typename T>
concept has_to_chars = requires(T v) { std::to_chars(nullptr, nullptr, std::declval<T>()); };

template <typename T>
concept has_from_chars = requires(T v) { std::from_chars(nullptr, nullptr, std::declval<T>()); };

template <typename T> std::string to_string(T value);

template <typename T> std::pair<bool, T> from_string(std::string_view str)
{
    T result;
    if constexpr (has_from_chars<T>) {
        const auto *end = str.data() + str.size();
        auto [endConv, err] = std::from_chars(str.data(), end, result);
        if (err == std::errc{} && endConv == end) {
            return {true, result};
        }
    } else {
        // NOLINTNEXTLINE(misc-const-correctness)
        std::istringstream iss(std::string{str});
        iss >> result;
        if (!iss.fail() && iss.eof()) {
            return {true, result};
        }
    }

    return {false, {}};
}

std::vector<std::string_view> split(std::string_view str, char sep);

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class null_ostream : public std::ostream {
public:
    null_ostream() = default;
    ~null_ostream() override = default;
    null_ostream(const null_ostream & /*unused*/) = delete;
    null_ostream(null_ostream && /*unused*/) = delete;
    null_ostream &operator=(const null_ostream & /*unused*/) = delete;
    null_ostream &operator=(null_ostream && /*unused*/) = delete;
};

template <class T> const null_ostream &operator<<(null_ostream &os, const T & /*unused*/)
{
    return os;
}

template <std::size_t N, std::size_t... I>
// NOLINTNEXTLINE(modernize-avoid-c-arrays,readability-named-parameter)
constexpr std::array<char, N> make_array(const char (&str)[N], std::index_sequence<I...>)
{
    return std::array<char, N>{tolower(str[I])...};
}

template <std::size_t N>
// NOLINTNEXTLINE(modernize-avoid-c-arrays)
constexpr bool string_iequals_literal(std::string_view left, const char (&right)[N])
{
    return left.size() == (N - 1) && std::equal(left.begin(), left.end(),
                                         make_array(right, std::make_index_sequence<N>()).begin(),
                                         [](char l, char r) { return tolower(l) == r; });
}

bool string_iequals(std::string_view left, std::string_view right);

std::vector<std::variant<std::string_view, int64_t>> convert_key_path(
    std::span<const std::variant<std::string, int64_t>> key_path);

} // namespace ddwaf
