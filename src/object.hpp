// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "ddwaf.h"
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace ddwaf {

enum class object_type : uint8_t {
    invalid = DDWAF_OBJ_INVALID,
    null = DDWAF_OBJ_NULL,
    boolean = DDWAF_OBJ_BOOL,
    int64 = DDWAF_OBJ_SIGNED,
    uint64 = DDWAF_OBJ_UNSIGNED,
    float64 = DDWAF_OBJ_FLOAT,
    string = DDWAF_OBJ_STRING,
    // const_string = DDWAF_OBJ_CONST_STRING,
    // small_string = DDWAF_OBJ_SMALL_STRING,
    array = DDWAF_OBJ_ARRAY,
    map = DDWAF_OBJ_MAP,
    // hash_map = DDWAF_OBJ_HASH_MAP
};

class [[gnu::may_alias]] array_object_view;
class [[gnu::may_alias]] map_object_view;

class [[gnu::may_alias]] object_view : protected ddwaf_object {
public:
    object_view() = delete;
    ~object_view() = delete;
    object_view(const object_view &) = delete;
    object_view(object_view &&) = delete;
    object_view &operator=(const object_view &) = delete;
    object_view &operator=(object_view &&) = delete;

    object_type type() const { return static_cast<object_type>(ddwaf_object::type); }
    std::size_t size() const { return static_cast<std::size_t>(nbEntries); }
    std::size_t length() const { return static_cast<std::size_t>(nbEntries); }
    // For future use
    std::size_t capacity() const { return static_cast<std::size_t>(nbEntries); }
    bool is_container() const { return type() == object_type::map || type() == object_type::array; }
    bool is_scalar() const
    {
        return type() == object_type::boolean || type() == object_type::int64 ||
               type() == object_type::uint64 || type() == object_type::float64 ||
               type() == object_type::string;
    }

    object_view *operator[](std::size_t index)
    {
        return reinterpret_cast<object_view *>(&array[index]);
    }

    const object_view *operator[](std::size_t index) const
    {
        return reinterpret_cast<const object_view *>(&array[index]);
    }

    bool has_key() const { return parameterName != nullptr; }
    std::string_view key() const
    {
        return {parameterName, static_cast<std::size_t>(parameterNameLength)};
    }

    template <typename T> std::optional<T> as_optional() const noexcept
    {
        if constexpr (std::is_same_v<T, const object_view *>) {
            return this;
        }

        if constexpr (std::is_same_v<T, const ddwaf_object *>) {
            return reinterpret_cast<T>(this);
        }

        if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>) {
            if (type() == object_type::string) {
                return T{stringValue, size()};
            }
        }

        if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, unsigned>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::uint64 && uintValue <= limits::max()) {
                return static_cast<T>(uintValue);
            }
        }

        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, int>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::int64 && intValue >= limits::min() &&
                intValue <= limits::max()) {
                return static_cast<T>(intValue);
            }
        }

        if constexpr (std::is_floating_point_v<T>) {
            using limits = std::numeric_limits<T>;
            if (type() == object_type::float64 && f64 >= limits::min() && f64 <= limits::max()) {
                return static_cast<T>(f64);
            }
        }

        if constexpr (std::is_same_v<T, bool>) {
            if (type() == object_type::boolean) {
                return static_cast<T>(boolean);
            }
        }

        return std::nullopt;
    }

    template <typename T> T as() const;

    /*template <> std::string_view as<std::string_view>() const*/
    /*{*/
    /*return std::string_view{stringValue, size()};*/
    /*}*/

    /*template <> array_object_view& as<array_object_view&>()*/
    /*{*/
    /*if (type() != object_type::array) {*/
    /*[[unlikely]] throw std::runtime_error("object_view not a array");*/
    /*}*/
    /*return reinterpret_cast<array_object_view&>(*this);*/
    /*}*/

    /*template <> map_object_view& as<map_object_view&>()*/
    /*{*/
    /*if (type() != object_type::map) {*/
    /*[[unlikely]] throw std::runtime_error("object_view not a map");*/
    /*}*/
    /*return reinterpret_cast<map_object_view&>(*this);*/
    /*}*/
    static object_view *from_native(const ddwaf_object *obj_ptr)
    {
        return reinterpret_cast<object_view *>(const_cast<ddwaf_object *>(obj_ptr));
    }
    static object_view &from_native(const ddwaf_object &obj_ref)
    {
        return reinterpret_cast<object_view &>(const_cast<ddwaf_object &>(obj_ref));
    }
    ddwaf_object *to_native() { return reinterpret_cast<ddwaf_object *>(this); }
    const ddwaf_object *to_native() const { return reinterpret_cast<const ddwaf_object *>(this); }
};

class [[gnu::may_alias]] array_object_view : public object_view {
public:
    array_object_view() = delete;
    ~array_object_view() = delete;
    array_object_view(const array_object_view &) = delete;
    array_object_view(array_object_view &&) = delete;
    array_object_view &operator=(const array_object_view &) = delete;
    array_object_view &operator=(array_object_view &&) = delete;

    object_type type() const { return object_type::map; }
    std::size_t size() const { return static_cast<std::size_t>(nbEntries); }
    std::size_t capacity() const { return static_cast<std::size_t>(nbEntries); }
    static array_object_view *from_native(const ddwaf_object *obj_ptr)
    {
        if (obj_ptr->type != DDWAF_OBJ_ARRAY) {
            [[unlikely]] throw std::runtime_error("ddwaf_object not a array");
        }
        return reinterpret_cast<array_object_view *>(const_cast<ddwaf_object *>(obj_ptr));
    }
    static array_object_view &from_native(const ddwaf_object &obj_ref)
    {
        if (obj_ref.type != DDWAF_OBJ_ARRAY) {
            [[unlikely]] throw std::runtime_error("ddwaf_object not a map");
        }
        return reinterpret_cast<array_object_view &>(const_cast<ddwaf_object &>(obj_ref));
    }
    class iterator {
    public:
        explicit iterator(array_object_view &ov, size_t index = 0)
            : current_(ov.array), end_(ov.array + ov.size())
        {
            if (index >= ov.size()) {
                throw std::out_of_range("iterator beyond map end");
            }
            current_ += index;
        }

        bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

        object_view *operator*() const noexcept
        {
            if (current_ == end_) {
                return nullptr;
            }
            return reinterpret_cast<object_view *>(current_);
        }

        iterator &operator++() noexcept
        {
            if (current_ != end_) {
                current_++;
            }
            return *this;
        }

    protected:
        ddwaf_object *current_{nullptr};
        ddwaf_object *end_{nullptr};
    };
};

class [[gnu::may_alias]] map_object_view : public object_view {
public:
    map_object_view() = delete;
    ~map_object_view() = delete;
    map_object_view(const map_object_view &) = delete;
    map_object_view(map_object_view &&) = delete;
    map_object_view &operator=(const map_object_view &) = delete;
    map_object_view &operator=(map_object_view &&) = delete;

    object_type type() const { return object_type::map; }
    std::size_t size() const { return static_cast<std::size_t>(nbEntries); }
    std::size_t capacity() const { return static_cast<std::size_t>(nbEntries); }
    static map_object_view *from_native(const ddwaf_object *obj_ptr)
    {
        if (obj_ptr->type != DDWAF_OBJ_MAP) {
            [[unlikely]] throw std::runtime_error("ddwaf_object not a map");
        }
        return reinterpret_cast<map_object_view *>(const_cast<ddwaf_object *>(obj_ptr));
    }
    static map_object_view &from_native(const ddwaf_object &obj_ref)
    {
        if (obj_ref.type != DDWAF_OBJ_MAP) {
            [[unlikely]] throw std::runtime_error("ddwaf_object not a map");
        }
        return reinterpret_cast<map_object_view &>(const_cast<ddwaf_object &>(obj_ref));
    }
    class iterator {
    public:
        explicit iterator(map_object_view &ov, size_t index = 0)
            : current_(ov.array), end_(ov.array + ov.size())
        {
            if (index >= ov.size()) {
                throw std::out_of_range("iterator beyond map end");
            }
            current_ += index;
        }

        bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

        std::string_view key() const noexcept
        {
            if (current_ == end_) {
                return {};
            }
            return {
                current_->parameterName, static_cast<std::size_t>(current_->parameterNameLength)};
        }

        object_view *value() const noexcept
        {
            if (current_ == end_) {
                return nullptr;
            }
            return reinterpret_cast<object_view *>(current_);
        }

        iterator &operator++() noexcept
        {
            if (current_ != end_) {
                current_++;
            }
            return *this;
        }

    protected:
        ddwaf_object *current_{nullptr};
        ddwaf_object *end_{nullptr};
    };
};

template <>
inline std::string_view object_view::as<std::string_view>() const
{
    return std::string_view{stringValue, size()};
}


class owned_object : protected ddwaf_object {
public:
};

class borrowed_object {
public:
protected:
    ddwaf_object *underlying_object_;
};
} // namespace ddwaf
