// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstring>
#include <optional>
#include <string_view>
#include <type_traits>

#include "ddwaf.h"
#include "object_type.hpp"

namespace ddwaf {

namespace detail {
using object = ddwaf_object;
/*struct object*/
/*{*/
    /*const char* parameterName;*/
    /*uint64_t parameterNameLength;*/
    /*// uintValue should be at least as wide as the widest type on the platform.*/
    /*union*/
    /*{*/
        /*const char* stringValue;*/
        /*uint64_t uintValue;*/
        /*int64_t intValue;*/
        /*object* array;*/
        /*bool boolean;*/
        /*double f64;*/
    /*};*/
    /*uint64_t nbEntries;*/
    /*object_type type;*/
/*};*/

struct object_iterator {
    const object *ptr;
    std::size_t index;
    std::size_t size;
    DDWAF_OBJ_TYPE type;
    // 1 byte of padding to spare

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    static object_iterator construct(
        const detail::object *obj, std::size_t index, std::size_t max_size)
    {
        if (obj->type == DDWAF_OBJ_MAP || obj->type == DDWAF_OBJ_ARRAY) {
            return {
                .ptr = obj->array,
                .index = index < obj->nbEntries ? index : static_cast<std::size_t>(obj->nbEntries),
                .size = obj->nbEntries < max_size ? static_cast<std::size_t>(obj->nbEntries) : max_size,
                .type = obj->type,
            };
        }

        return {
            .ptr = nullptr,
            .index = 0,
            .size = 0,
            .type = DDWAF_OBJ_INVALID,
        };
    }

    object_iterator &operator++() noexcept
    {
        if (index < size) {
            ++index;
        }
        return *this;
    }

    std::pair<std::string_view, const detail::object *> operator*() const noexcept
    {
        if (index < size) {
            const auto &slot = ptr[index];
            std::string_view key;
            if (type == DDWAF_OBJ_MAP) {
                key = {slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
            }

            return {key, &slot};
        }

        [[unlikely]] return {};
    }

    [[nodiscard]] bool is_valid() const noexcept { return index < size; }

    [[nodiscard]] std::string_view key() const noexcept
    {
        if (type != DDWAF_OBJ_MAP || index >= size) { [[unlikely]]
            return {};
        }
        const auto &slot = ptr[index];
        return {slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
    }

    [[nodiscard]] const object *value() const noexcept
    {
        if (index >= size) { [[unlikely]]
            return nullptr;
        }
        return &ptr[index];
    }
};
} // namespace detail

template <typename T> struct converter;

class object_view {
public:
    class map;
    class array;

    object_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object *underlying_object) : obj_(underlying_object) {}
    ~object_view() = default;
    object_view(const object_view &) = default;
    object_view(object_view &&) = default;
    object_view &operator=(const object_view &) = default;
    object_view &operator=(object_view &&) = default;

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    [[nodiscard]] object_type type() const noexcept
    {
        if (obj_ == nullptr) {
            [[unlikely]] return object_type::invalid;
        }
        return static_cast<object_type>(obj_->type);
    }
    [[nodiscard]] std::size_t size() const noexcept
    {
        if (!is_container()) {
            [[unlikely]] return 0;
        }
        return static_cast<std::size_t>(obj_->nbEntries);
    }
    [[nodiscard]] std::size_t capacity() const noexcept
    {
        if (!is_container()) {
            [[unlikely]] return 0;
        }
        return static_cast<std::size_t>(obj_->nbEntries);
    }
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    template <typename T> [[nodiscard]] bool is() const noexcept
    {
        return is_compatible_type<T>(type());
    }
    [[nodiscard]] bool is_valid() const noexcept
    {
        return type() != object_type::invalid;
    }
    [[nodiscard]] bool is_invalid() const noexcept
    {
        return type() == object_type::invalid;
    }
    [[nodiscard]] bool is_container() const noexcept
    {
        return (type() & container_object_type) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept
    {
        return (type() & scalar_object_type) != 0;
    }
    [[nodiscard]] bool is_string() const noexcept
    {
        return type() == object_type::string;
    }
    bool operator==(const object_view other) const { return ptr() == other.ptr(); }
    bool operator!=(const object_view other) const { return ptr() != other.ptr(); }

    [[nodiscard]] const detail::object *ptr() const { return obj_; }

    [[nodiscard]] std::pair<std::string_view, object_view> at(std::size_t index) const noexcept
    {
        if (!is_container() || index > size()) {
            [[unlikely]] return {};
        }
        return at_unchecked(index);
    }

    [[nodiscard]] std::pair<std::string_view, object_view> at_unchecked(std::size_t index) const noexcept
    {
        if (type() == object_type::map) {
            auto &slot = obj_->array[index];
            std::string_view key{slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
            return {key, object_view{&slot}};
        }

        auto &slot = obj_->array[index];
        return {{}, object_view{&slot}};
    }

    template <typename T> [[nodiscard]] std::optional<T> as() const noexcept
    {
        if (!is_compatible_type<T>(type())) {
            return std::nullopt;
        }
        return as_unchecked<T>();
    }

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view>
    {
        return {*this};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, object_view>
    {
        return {obj_};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, bool>
    {
        return obj_->boolean;
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_integral_v<T> && std::is_signed_v<T> && (!std::is_same_v<T, bool>)
    {
        return static_cast<T>(obj_->intValue);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
    {
        return static_cast<T>(obj_->uintValue);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_floating_point_v<T>
    {
        return static_cast<T>(obj_->f64);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        return {obj_->stringValue, size()};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, const char *>
    {
        return obj_->stringValue;
    }

    template <typename T> T convert() const { return converter<T>{*this}(); }

    class array {
    public:
        array() = default;
        ~array() = default;
        array(const array &) = default;
        array(array &&) = default;
        array &operator=(const array &) = default;
        array &operator=(array &&) = default;

        [[nodiscard]] std::size_t size() const noexcept
        {
            if (obj_ == nullptr) {
                return 0;
            }
            return static_cast<std::size_t>(obj_->nbEntries);
        }
        [[nodiscard]] std::size_t capacity() const noexcept
        {
            if (obj_ == nullptr) {
                return 0;
            }
            return static_cast<std::size_t>(obj_->nbEntries);
        }

        [[nodiscard]] bool empty() const { return size() == 0; }

        [[nodiscard]] const detail::object *ptr() const { return obj_; }

        [[nodiscard]] object_view at(std::size_t index) const noexcept
        {
            if (index >= size()) {
                [[unlikely]] return {};
            }
            return at_unchecked(index);
        }

        [[nodiscard]] object_view at_unchecked(std::size_t index) const noexcept
        {
            if (obj_ == nullptr) {
                return {};
            }
            return &obj_->array[index];
        }

        class iterator {
        public:
            iterator() = default;
            explicit iterator(array &ov, size_t index = 0)
                : current_(ov.obj_->array), end_(ov.obj_->array + ov.size())
            {
                if (index >= ov.size()) {
                    current_ = end_;
                } else {
                    current_ += index;
                }
            }

            bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

            object_view operator*() const noexcept
            {
                if (current_ == end_) {
                    return nullptr;
                }
                return {current_};
            }

            iterator &operator++() noexcept
            {
                if (current_ != end_) {
                    current_++;
                }
                return *this;
            }

        protected:
            detail::object *current_{nullptr};
            detail::object *end_{nullptr};
        };

        iterator begin()
        {
            if (obj_ == nullptr) {
                return {};
            }
            return iterator{*this, 0};
        }
        iterator end()
        {
            if (obj_ == nullptr) {
                return {};
            }
            return iterator{*this, static_cast<std::size_t>(obj_->nbEntries)};
        }

    protected:
        friend class object_view;

        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        explicit array(const detail::object *underlying_object) : obj_(underlying_object) {}

        const detail::object *obj_{nullptr};
    };

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view::array>
    {
        if (type() == object_type::array) {
            return std::nullopt;
        }
        return as_unchecked<object_view::array>();
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, array>
    {
        return T{obj_};
    }

    class map {
    public:
        ~map() = default;
        map(const map &) = default;
        map(map &&) = default;
        map &operator=(const map &) = default;
        map &operator=(map &&) = default;

        [[nodiscard]] std::size_t size() const noexcept
        {
            if (obj_ == nullptr) {
                return 0;
            }
            return static_cast<std::size_t>(obj_->nbEntries);
        }
        [[nodiscard]] std::size_t capacity() const noexcept
        {
            if (obj_ == nullptr) {
                return 0;
            }
            return static_cast<std::size_t>(obj_->nbEntries);
        }

        [[nodiscard]] bool empty() const { return size() == 0; }

        [[nodiscard]] const detail::object *ptr() const { return obj_; }

        [[nodiscard]] object_view at(std::string_view key) const
        {
            for (std::size_t i = 0; i < size(); ++i) {
                auto &slot = obj_->array[i];
                std::string_view current_key{slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
                if (current_key == key) {
                    return {&slot};
                }
            }
            return {};
        }

        template <typename KeyType = std::string_view>
        std::optional<std::pair<KeyType, object_view>> at(std::size_t index)
            requires std::is_same_v<KeyType, std::string> ||
                     std::is_same_v<KeyType, std::string_view> ||
                     std::is_same_v<KeyType, object_view>
        {
            if (index > size()) {
                [[unlikely]] return {};
            }
            return at_unchecked<KeyType>(index);
        }

        template <typename KeyType = std::string_view>
        std::pair<KeyType, object_view> at_unchecked(std::size_t index)
            requires std::is_same_v<KeyType, std::string> ||
                     std::is_same_v<KeyType, std::string_view> ||
                     std::is_same_v<KeyType, object_view>
        {
            auto &slot = obj_->array[index];
            std::string_view key{slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
            return {key, object_view{&slot}};
        }

        class iterator {
        public:
            explicit iterator(map &ov, size_t index = 0)
                : current_(ov.obj_->array), end_(ov.obj_->array + ov.size())
            {
                if (index >= ov.size()) {
                    current_ = end_;
                } else {
                    current_ += index;
                }
            }

            bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

            [[nodiscard]] std::string_view key() const noexcept
            {
                if (current_ == end_) {
                    return {};
                }
                return {current_->parameterName, static_cast<std::size_t>(current_->parameterNameLength)};
            }

            std::pair<std::string_view, object_view> operator*() const noexcept
            {
                if (current_ == end_) {
                    return {{}, nullptr};
                }
                return {key(), value()};
            }

            [[nodiscard]] object_view value() const noexcept
            {
                if (current_ == end_) {
                    return nullptr;
                }
                return {current_};
            }

            iterator &operator++() noexcept
            {
                if (current_ != end_) {
                    current_++;
                }
                return *this;
            }

        protected:
            detail::object *current_{nullptr};
            detail::object *end_{nullptr};
        };

        iterator begin() { return iterator{*this, 0}; }

        iterator end() { return iterator{*this, static_cast<std::size_t>(obj_->nbEntries)}; }

    protected:
        friend class object_view;

        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        explicit map(const detail::object *underlying_object) : obj_(underlying_object) {}

        const detail::object *obj_;
    };

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view::map>
    {
        if (type() == object_type::map) {
            return std::nullopt;
        }
        return as_unchecked<object_view::map>();
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, object_view::map>
    {
        return T{obj_};
    }

protected:
    const detail::object *obj_{nullptr};
};

} // namespace ddwaf
namespace std {

template <> struct hash<ddwaf::object_view> {
    auto operator()(const ddwaf::object_view &obj) const
    {
        return std::hash<const void *>{}(static_cast<const void *>(obj.ptr()));
    }
};

} // namespace std
