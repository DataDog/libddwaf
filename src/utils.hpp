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
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <type_traits>

#include "ddwaf.h"

// Convert numbers to strings
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

template <typename T> using optional_ref = std::optional<std::reference_wrapper<T>>;

// Internals
// clang-format off
#define PWI_DATA_TYPES (DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED | DDWAF_OBJ_STRING | DDWAF_OBJ_BOOL | DDWAF_OBJ_FLOAT)
#define PWI_CONTAINER_TYPES (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP)
#define DDWAF_RESULT_INITIALISER {false,  {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_MAP}, 0}
// clang-format on

namespace ddwaf {

struct eval_result {
    bool outcome;
    bool ephemeral;
};

struct object_limits {
    static constexpr uint32_t default_max_container_depth{DDWAF_MAX_CONTAINER_DEPTH};
    static constexpr uint32_t default_max_container_size{DDWAF_MAX_CONTAINER_SIZE};
    static constexpr uint32_t default_max_string_length{DDWAF_MAX_STRING_LENGTH};

    uint32_t max_container_depth{DDWAF_MAX_CONTAINER_DEPTH};
    uint32_t max_container_size{DDWAF_MAX_CONTAINER_SIZE};
    uint32_t max_string_length{DDWAF_MAX_STRING_LENGTH};
};

using target_index = std::size_t;

inline target_index get_target_index(std::string_view address)
{
    return std::hash<std::string_view>{}(address);
}

inline size_t find_string_cutoff(const char *str, size_t length, object_limits limits = {})
{
    // If the string is shorter than our cap, then fine
    if (length <= limits.max_string_length) {
        return length;
    }

    // If it's longer, we need to truncate it. However, we don't want to cut a UTF-8 byte sequence
    // in the middle of it! Valid UTF8 has a specific binary format. 	If it's a single byte UTF8
    // character, then it is always of form '0xxxxxxx', where 'x' is any binary digit. 	If it's a
    // two byte UTF8 character, then it's always of form '110xxxxx 10xxxxxx'. 	Similarly for three
    // and four byte UTF8 characters it starts with '1110xxxx' and '11110xxx' followed 		by
    // '10xxxxxx' one less times as there are bytes.

    // We take the two strongest bits of the first trimmed character. We have four possibilities:
    //  - 00 or 01: single UTF-8 byte, no risk trimming
    //  - 11: New multi-byte sequence, we can ignore it, no risk trimming
    //  - 10: Middle of multi byte sequence, we need to step back
    //  We therefore loop as long as we see the '10' sequence

    size_t pos = limits.max_string_length;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    while (pos != 0 && (str[pos] & 0xC0) == 0x80) { pos -= 1; }

    return pos;
}

namespace object {

inline bool is_container(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type & PWI_CONTAINER_TYPES) != 0 && obj->array != nullptr;
}

inline bool is_map(const ddwaf_object *obj)
{
    return obj != nullptr && obj->type == DDWAF_OBJ_MAP && obj->array != nullptr;
}

inline bool is_scalar(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type & PWI_DATA_TYPES) != 0;
}

inline bool is_invalid_or_null(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type == DDWAF_OBJ_INVALID || obj->type == DDWAF_OBJ_NULL);
}

ddwaf_object clone(ddwaf_object *input);
} // namespace object

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

inline std::string object_to_string(const ddwaf_object &object)
{
    if (object.type == DDWAF_OBJ_STRING) {
        return std::string{object.stringValue, static_cast<std::size_t>(object.nbEntries)};
    }

    if (object.type == DDWAF_OBJ_BOOL) {
        return to_string<std::string>(object.boolean);
    }

    if (object.type == DDWAF_OBJ_SIGNED) {
        return to_string<std::string>(object.intValue);
    }

    if (object.type == DDWAF_OBJ_UNSIGNED) {
        return to_string<std::string>(object.uintValue);
    }

    if (object.type == DDWAF_OBJ_FLOAT) {
        return to_string<std::string>(object.f64);
    }

    return {};
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

} // namespace ddwaf
