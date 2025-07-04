// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

// Convert numbers to strings
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
// (string, length), only for literals
#define STRL(value) value, sizeof(value) - 1

template <typename T> using optional_ref = std::optional<std::reference_wrapper<T>>;

namespace ddwaf {

struct eval_result {
    bool outcome;
    bool ephemeral;
};

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

template <class Fn> class scope_exit {
public:
    explicit scope_exit(Fn &&fn) noexcept : fn_(std::move(fn)) {}
    ~scope_exit() { fn_(); }

    scope_exit(const scope_exit &) = delete;
    scope_exit(scope_exit &&) = delete;
    scope_exit &operator=(const scope_exit &) = delete;
    scope_exit &operator=(scope_exit &&) = delete;

protected:
    Fn fn_;
};

template <typename T>
concept has_to_chars = requires(T v) { std::to_chars(nullptr, nullptr, std::declval<T>()); };

template <typename T>
concept has_from_chars = requires(T v) { std::from_chars(nullptr, nullptr, std::declval<T>()); };

template <typename StringType, typename T>
StringType to_string(T value)
    requires std::is_integral_v<T> && (!std::is_same_v<T, bool>) &&
             std::is_same_v<StringType, std::basic_string<char, typename StringType::traits_type,
                                            typename StringType::allocator_type>>
{
    // Maximum number of characters required to represent a 64 bit integer as a string
    // 20 bytes for UINT64_MAX or INT64_MIN
    static constexpr size_t max_chars = 20;

    std::array<char, max_chars> str{};
    auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value);
    [[unlikely]] if (ec != std::errc()) {
        return {};
    }
    return {str.data(), ptr};
}

template <typename T>
    requires std::is_same_v<T, float> || std::is_same_v<T, double>
// XXX: add long double, though it's tricker, we don't know if it's quad-precision
// or x87 80-bit "extended precision" or even the same as double
inline constexpr std::size_t max_exp_digits = sizeof(T) == 4 ? 2 : 4;

template <typename StringType, typename T>
StringType to_string(T value)
    requires(std::is_same_v<T, float> || std::is_same_v<T, double>) &&
            std::is_same_v<StringType, std::basic_string<char, typename StringType::traits_type,
                                           typename StringType::allocator_type>>
{
    if constexpr (has_to_chars<T>) {
        static constexpr std::size_t max_chars = std::numeric_limits<T>::digits10 + 1 +
                                                 1 /* sign */ + 1 /* dot */ + 1 /* e */ +
                                                 1 /* exp sign */
                                                 + (sizeof(T) == 4 ? 2 : 4);

        std::array<char, max_chars> str{};
        auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value);
        [[unlikely]] if (ec != std::errc()) {
            // This is likely unreachable if the max_chars calculation is accurate
            return {};
        }
        return {str.data(), ptr};
    } else {
        using char_type = typename StringType::value_type;
        using traits_type = typename StringType::traits_type;
        using allocator_type = typename StringType::allocator_type;
        std::basic_ostringstream<char_type, traits_type, allocator_type> ss;
        ss << std::setprecision(std::numeric_limits<T>::digits10) << value;
        return std::move(ss).str();
    }
}

template <typename StringType, typename T>
StringType to_string(T value)
    requires std::is_same_v<T, bool> &&
             std::is_same_v<StringType, std::basic_string<char, typename StringType::traits_type,
                                            typename StringType::allocator_type>>
{
    return value ? "true" : "false";
}

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
        std::istringstream iss(std::string{str});
        iss >> result;
        if (!iss.fail() && iss.eof()) {
            return {true, result};
        }
    }

    return {false, {}};
}

inline std::vector<std::string_view> split(std::string_view str, char sep)
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
constexpr std::array<char, N> make_array(const char (&str)[N], std::index_sequence<I...>)
{
    return std::array<char, N>{tolower(str[I])...};
}

template <std::size_t N>
constexpr inline bool string_iequals_literal(std::string_view left, const char (&right)[N])
{
    return left.size() == (N - 1) && std::equal(left.begin(), left.end(),
                                         make_array(right, std::make_index_sequence<N>()).begin(),
                                         [](char l, char r) { return tolower(l) == r; });
}

inline bool string_iequals(std::string_view left, std::string_view right)
{
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin(),
               [](char l, char r) { return tolower(l) == tolower(r); });
}

} // namespace ddwaf
