// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <ddwaf.h>
#include <functional>
#include <iterator>
#include <optional>
#include <string>
#include <unordered_map>

// Convert numbers to strings
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

template <typename T> using optional_ref = std::optional<std::reference_wrapper<T>>;

size_t find_string_cutoff(
    const char *str, size_t length, uint32_t max_string_length = DDWAF_MAX_STRING_LENGTH);

// Internals
// clang-format off
#define PWI_DATA_TYPES (DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED | DDWAF_OBJ_STRING)
#define PWI_CONTAINER_TYPES (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP)
#define DDWAF_RESULT_INITIALISER {false,  {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, 0}
// clang-format on

namespace ddwaf {

using target_index = std::size_t;

inline target_index get_target_index(const std::string &address)
{
    return std::hash<std::string>{}(address);
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
inline bool isdigit(char c) { return (c >= '0' && c <= '9'); }
inline bool isxdigit(char c)
{
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}
inline bool isspace(char c)
{
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}
inline bool isupper(char c) { return (c >= 'A' && c <= 'Z'); }
inline bool isalnum(char c) { return isalpha(c) || isdigit(c); }
inline char tolower(char c) { return isupper(c) ? static_cast<char>(c | 0x20) : c; }
inline uint8_t from_hex(char c)
{
    if (ddwaf::isdigit(c)) {
        return static_cast<uint8_t>(c - '0');
    }
    return static_cast<uint8_t>((c | 0x20) - 'a' + 0xa);
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

} // namespace ddwaf
