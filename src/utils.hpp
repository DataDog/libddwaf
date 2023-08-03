// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <ddwaf.h>
#include <functional>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>
#include <unordered_map>

// Convert numbers to strings
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

template <typename T> using optional_ref = std::optional<std::reference_wrapper<T>>;

// Internals
// clang-format off
#define PWI_DATA_TYPES (DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED | DDWAF_OBJ_STRING | DDWAF_OBJ_BOOL)
#define PWI_CONTAINER_TYPES (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP)
#define DDWAF_RESULT_INITIALISER {false,  {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, 0}
// clang-format on

namespace ddwaf {

struct object_limits {
    uint32_t max_container_depth{DDWAF_MAX_CONTAINER_DEPTH};
    uint32_t max_container_size{DDWAF_MAX_CONTAINER_SIZE};
    uint32_t max_string_length{DDWAF_MAX_STRING_LENGTH};
};

using target_index = std::size_t;

inline target_index get_target_index(const std::string &address)
{
    return std::hash<std::string>{}(address);
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

template <typename StringType, typename T>
StringType to_string(T value)
    requires std::is_integral_v<T>
{
    // Maximum number of characters required to represent a 64 bit integer as a string
    // 20 bytes for UINT64_MAX or INT64_MIN + null byte
    static constexpr size_t uint64_max_chars = 21;

    std::array<char, uint64_max_chars> str{};
    auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value);
    if (ec == std::errc()) {
        return {str.data(), ptr};
    }
    return {};
}

template <typename StringType> StringType to_string(bool value) { return value ? "true" : "false"; }

} // namespace ddwaf
