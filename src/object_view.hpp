// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "exception.hpp"
#include <ddwaf.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf {

enum class object_type : unsigned {
    invalid = DDWAF_OBJ_INVALID,
    boolean = DDWAF_OBJ_BOOL,
    int64 = DDWAF_OBJ_SIGNED,
    uint64 = DDWAF_OBJ_UNSIGNED,
    string = DDWAF_OBJ_STRING,
    map = DDWAF_OBJ_MAP,
    array = DDWAF_OBJ_ARRAY
};

class object_view {
public:
    using map = std::unordered_map<std::string_view, object_view>;
    using vector = std::vector<object_view>;
    using string_set = std::unordered_set<std::string_view>;

    class iterator {
    public:
        explicit iterator(const ddwaf_object &obj, size_t index = 0)
            : current_(obj.array + (index < obj.nbEntries ? index : obj.nbEntries)),
              end_(obj.array + obj.nbEntries)
        {}

        bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

        object_view operator*() const noexcept { return object_view{current_}; }

        iterator &operator++() noexcept
        {
            if (current_ != end_) {
                current_++;
            }
            return *this;
        }

    protected:
        const ddwaf_object *current_{nullptr};
        const ddwaf_object *end_{nullptr};
    };

    explicit object_view(const ddwaf_object *ptr) : ptr_(ptr)
    {
        if (ptr_ == nullptr) {
            throw std::runtime_error("object_view initialised with null pointer");
        }
    }
    explicit object_view(const ddwaf_object &ptr) : ptr_(&ptr) {}

    ~object_view() = default;

    object_view(const object_view &other) = default;
    object_view &operator=(const object_view &other) = default;

    object_view(object_view &&other) = delete;
    object_view &operator=(object_view &&other) = delete;

    // Container size
    [[nodiscard]] object_type type() const noexcept { return static_cast<object_type>(ptr_->type); }
    [[nodiscard]] size_t size() const noexcept
    {
        if (!is_container()) {
            return 0;
        }
        return static_cast<size_t>(ptr_->nbEntries);
    }
    [[nodiscard]] size_t length() const noexcept
    {
        if (!is_string()) {
            return 0;
        }
        return static_cast<size_t>(ptr_->nbEntries);
    }
    [[nodiscard]] bool has_key() const noexcept { return ptr_->parameterName != nullptr; }
    [[nodiscard]] std::string_view key() const noexcept
    {
        return {ptr_->parameterName, ptr_->parameterNameLength};
    }

    // Scalars
    bool is_invalid() const noexcept { return type() == object_type::invalid; }
    bool is_boolean() const noexcept { return type() == object_type::boolean; }
    bool is_signed() const noexcept { return type() == object_type::int64; }
    bool is_unsigned() const noexcept { return type() == object_type::uint64; }
    bool is_string() const noexcept { return type() == object_type::string; }
    bool is_scalar() const noexcept
    {
        return is_boolean() || is_signed() || is_unsigned() || is_string();
    }

    // Containers
    bool is_array() const noexcept { return type() == object_type::array; }
    bool is_map() const noexcept { return type() == object_type::map; }
    bool is_container() const noexcept { return is_array() || is_map(); }

    [[nodiscard]] iterator begin() const
    {
        if (!is_container()) {
            throw std::runtime_error("object_view not a container");
        }
        return iterator(*ptr_);
    }
    [[nodiscard]] iterator end() const
    {
        if (!is_container()) {
            throw std::runtime_error("object_view not a container");
        }
        return iterator(*ptr_, size());
    }

    object_view operator[](size_t index) const
    {
        if (!is_container()) {
            throw std::runtime_error("parameter not a container");
        }

        if (index >= size()) {
            throw std::out_of_range("index(" + std::to_string(index) + ") out of range(" +
                                    std::to_string(size()) + ")");
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
        return object_view{&ptr_->array[index]};
    }

    operator const ddwaf_object *() noexcept { return ptr_; }

    explicit operator map() const;
    explicit operator vector() const;
    explicit operator string_set() const;
    explicit operator std::string_view() const;
    explicit operator std::string() const;
    explicit operator uint64_t() const;
    explicit operator int64_t() const;
    explicit operator bool() const;
    explicit operator std::vector<std::string>() const;
    explicit operator std::vector<std::string_view>() const;

protected:
    const ddwaf_object *ptr_;
};

// template <typename T> struct object_view_traits {
// static const char *name() { return typeid(T).name(); }
//};

// template <> struct object_view_traits<std::string> {
// static const char *name() { return "std::string"; }
//};

// template <> struct object_view_traits<std::string_view> {
// static const char *name() { return "std::string_view"; }
//};

// template <> struct object_view_traits<object_view::map> {
// static const char *name() { return "object_view::map"; }
//};

// template <> struct object_view_traits<object_view::vector> {
// static const char *name() { return "object_view::vector"; }
//};

// template <> struct object_view_traits<object_view::string_set> {
// static const char *name() { return "object_view::string_set"; }
//};

// template <> struct object_view_traits<std::vector<std::string>> {
// static const char *name() { return "std::vector<std::string>"; }
//};

// template <> struct object_view_traits<std::vector<std::string_view>> {
// static const char *name() { return "std::vector<std::string_view>"; }
//};

} // namespace ddwaf
