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
#include "utils.hpp"

namespace ddwaf {

namespace detail {
using object = ddwaf_object;
} // namespace detail

template <typename T> struct converter;

class object_view {
public:
    // The default constructor results in a view without value
    object_view() = default;

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object *underlying_object) : obj_(underlying_object) {}

    ~object_view() = default;
    object_view(const object_view &) = default;
    object_view(object_view &&) = default;
    object_view &operator=(const object_view &) = default;
    object_view &operator=(object_view &&) = default;

    [[nodiscard]] const detail::object *ptr() const { return obj_; }
    bool operator==(const object_view other) const { return ptr() == other.ptr(); }
    bool operator!=(const object_view other) const { return ptr() != other.ptr(); }

    // The unchecked API assumes that the caller has already verified that the
    // method preconditions are met:
    //   - The underlying object is non-null (using has_value());
    //   - When using at, the accessed indexed is within bounds (using size*())
    //   - When using as, the accessed field matches the underlying object type (using is*())
    //
    // The checked API (without suffix), always validates preconditions so it is
    // safer but introduces small overheads.

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    [[nodiscard]] object_type type_unchecked() const noexcept
    {
        return static_cast<object_type>(obj_->type);
    }

    [[nodiscard]] object_type type() const noexcept
    {
        return obj_ != nullptr ? type_unchecked() : object_type::invalid;
    }

    // Size and empty methods apply to both containers and strings
    [[nodiscard]] std::size_t size_unchecked() const noexcept
    {
        return static_cast<std::size_t>(obj_->nbEntries);
    }
    [[nodiscard]] std::size_t size() const noexcept
    {
        return obj_ != nullptr ? size_unchecked() : 0;
    }

    [[nodiscard]] bool empty_unchecked() const noexcept { return obj_->nbEntries == 0; }

    [[nodiscard]] bool empty() const noexcept { return obj_ != nullptr ? empty_unchecked() : true; }

    // is<T> check whether the underlying type is compatible with the required
    // type. When it comes to numeric types, the request type must match the
    // one used within ddwaf_object, i.e. the type will not be cast to one of
    // a smaller size.
    template <typename T> [[nodiscard]] bool is() const noexcept
    {
        return obj_ != nullptr && is_compatible_type<T>(type_unchecked());
    }

    // These is_* methods provide further checks for consistency, albeit these
    // perhaps should be replaced by assertions.
    [[nodiscard]] bool is_container() const noexcept
    {
        return obj_ != nullptr && (type_unchecked() & container_object_type) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept
    {
        return obj_ != nullptr && (type_unchecked() & scalar_object_type) != 0;
    }

    // Access the key and value at index. If the container is an array, the key
    // will be an empty string.
    [[nodiscard]] std::pair<std::string_view, object_view> at_unchecked(
        std::size_t index) const noexcept
    {
        auto &slot = obj_->array[index];
        std::string_view key{
            slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
        return {key, object_view{&slot}};
    }

    [[nodiscard]] std::pair<std::string_view, object_view> at(std::size_t index) const noexcept
    {
        if (!is_container() || index > static_cast<std::size_t>(obj_->nbEntries)) {
            [[unlikely]] return {};
        }
        return at_unchecked(index);
    }

    // Access the underlying value based on the required type
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

    // Access the underlying value based on the required type, these methods
    // return an optional which will have no value if the requested type doesn't
    // match the underlying type of this object_view.
    template <typename T> [[nodiscard]] std::optional<T> as() const noexcept
    {
        if (!is_compatible_type<T>(type())) {
            [[unlikely]] return std::nullopt;
        }
        return as_unchecked<T>();
    }

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view>
    {
        return {*this};
    }

    // Convert the underlying type to the requested type
    template <typename T> T convert() const { return converter<T>{*this}(); }

    class iterator {
    public:
        ~iterator() = default;
        iterator(const iterator &) = default;
        iterator(iterator &&) = default;
        iterator &operator=(const iterator &) = default;
        iterator &operator=(iterator &&) = default;

        [[nodiscard]] object_type container_type() const noexcept { return type_; }

        // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
        operator bool() const noexcept { return index_ < size_; }

        bool operator!=(const iterator &rhs) const noexcept
        {
            return obj_ != rhs.obj_ || index_ != rhs.index_;
        }

        [[nodiscard]] std::string_view key() const
        {
            if (index_ >= size_) {
                [[unlikely]] return {};
            }

            auto &slot = obj_->array[index_];
            std::string_view key{
                slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
            return key;
        }

        [[nodiscard]] object_view value() const
        {
            if (index_ >= size_) {
                [[unlikely]] return {};
            }

            return &obj_->array[index_];
        }

        std::pair<std::string_view, object_view> operator*() const
        {
            if (index_ >= size_) {
                [[unlikely]] return {};
            }

            auto &slot = obj_->array[index_];
            std::string_view key{
                slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
            return {key, &slot};
        }

        [[nodiscard]] std::size_t index() const { return static_cast<std::size_t>(index_); }

        iterator &operator++() noexcept
        {
            // Saturated increment (to size)
            index_ += static_cast<uint32_t>(index_ < size_);
            return *this;
        }

        [[nodiscard]] iterator prev() const noexcept
        {
            // Saturated decrement (to 0)
            auto new_index = static_cast<uint16_t>(index_ - static_cast<uint16_t>(index_ > 0));
            return {obj_, size_, new_index, type_};
        }

    protected:
        iterator() = default;

        explicit iterator(
            const detail::object *obj, const object_limits &limits = {}, uint16_t idx = 0)
            : obj_(obj), size_(std::min(static_cast<uint16_t>(limits.max_container_size),
                             static_cast<uint16_t>(obj->nbEntries))),
              index_(std::min(idx, size_)), type_(static_cast<object_type>(obj->type))
        {}

        iterator(
            // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
            const detail::object *obj, std::uint16_t size, std::uint16_t index, object_type type)
            : obj_(obj), size_(size), index_(index), type_(type)
        {}

        const detail::object *obj_{nullptr};
        std::uint16_t size_{0};
        std::uint16_t index_{0};
        object_type type_{object_type::invalid};

        friend class object_view;
    };

    iterator begin(const object_limits &limits = {})
    {
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{obj_, limits};
    }

    iterator end()
    {
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{obj_, {}, size_unchecked()};
    }

    // Container abstractions, for convenience

    // Array abstraction, allows access only to values, but not keys
    class array {
    public:
        array() = default;
        ~array() = default;
        array(const array &) = default;
        array(array &&) = default;
        array &operator=(const array &) = default;
        array &operator=(array &&) = default;

        [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

        // Size and empty methods apply to both containers and strings
        [[nodiscard]] std::size_t size_unchecked() const noexcept
        {
            return static_cast<std::size_t>(obj_->nbEntries);
        }
        [[nodiscard]] std::size_t size() const noexcept
        {
            return obj_ != nullptr ? size_unchecked() : 0;
        }

        [[nodiscard]] bool empty_unchecked() const noexcept { return obj_->nbEntries == 0; }

        [[nodiscard]] bool empty() const noexcept
        {
            return obj_ != nullptr ? empty_unchecked() : true;
        }

        [[nodiscard]] const detail::object *ptr() const noexcept { return obj_; }

        // Access the key and value at index. If the container is an array, the key
        // will be an empty string.
        [[nodiscard]] object_view at_unchecked(std::size_t index) const noexcept
        {
            return &obj_->array[index];
        }

        [[nodiscard]] object_view at(std::size_t index) const noexcept
        {
            if (obj_ != nullptr || index > size_unchecked()) {
                [[unlikely]] return {};
            }
            return at_unchecked(index);
        }

        class iterator {
        public:
            bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

            object_view operator*() const noexcept { return current_ != end_ ? current_ : nullptr; }

            iterator &operator++() noexcept
            {
                if (current_ != end_) {
                    [[likely]] current_++;
                }
                return *this;
            }

        protected:
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

            detail::object *current_{nullptr};
            detail::object *end_{nullptr};

            friend class array;
        };

        iterator begin() { return obj_ != nullptr ? iterator{*this} : iterator{}; }
        iterator end() { return obj_ != nullptr ? iterator{*this, size_unchecked()} : iterator{}; }

    protected:
        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        explicit array(const detail::object *underlying_object) : obj_(underlying_object) {}

        const detail::object *obj_{nullptr};

        friend class object_view;
    };

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view::array>
    {
        if (type() != object_type::array) {
            [[unlikely]] return std::nullopt;
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
        map() = default;
        ~map() = default;
        map(const map &) = default;
        map(map &&) = default;
        map &operator=(const map &) = default;
        map &operator=(map &&) = default;

        // Size and empty methods apply to both containers and strings
        [[nodiscard]] std::size_t size_unchecked() const noexcept
        {
            return static_cast<std::size_t>(obj_->nbEntries);
        }
        [[nodiscard]] std::size_t size() const noexcept
        {
            return obj_ != nullptr ? size_unchecked() : 0;
        }

        [[nodiscard]] bool empty_unchecked() const noexcept { return obj_->nbEntries == 0; }

        [[nodiscard]] bool empty() const noexcept
        {
            return obj_ != nullptr ? empty_unchecked() : true;
        }

        [[nodiscard]] const detail::object *ptr() const noexcept { return obj_; }

        [[nodiscard]] object_view at(std::string_view key) const
        {
            if (obj_ == nullptr) {
                [[unlikely]] return {};
            }

            for (std::size_t i = 0; i < size(); ++i) {
                auto &slot = obj_->array[i];
                std::string_view current_key{
                    slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
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
            if (obj_ == nullptr || index > size_unchecked()) {
                [[unlikely]] return std::nullopt;
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
            std::string_view key{
                slot.parameterName, static_cast<std::size_t>(slot.parameterNameLength)};
            return {key, object_view{&slot}};
        }

        class iterator {
        public:
            bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

            [[nodiscard]] std::string_view key() const noexcept
            {
                if (current_ == end_) {
                    [[unlikely]] return {};
                }
                return {current_->parameterName,
                    static_cast<std::size_t>(current_->parameterNameLength)};
            }

            std::pair<std::string_view, object_view> operator*() const noexcept
            {
                if (current_ == end_) {
                    [[unlikely]] return {{}, nullptr};
                }
                return {key(), value()};
            }

            [[nodiscard]] object_view value() const noexcept
            {
                if (current_ == end_) {
                    [[unlikely]] return nullptr;
                }
                return {current_};
            }

            iterator &operator++() noexcept
            {
                if (current_ != end_) {
                    [[likely]] current_++;
                }
                return *this;
            }

        protected:
            iterator() = default;
            explicit iterator(map &ov, size_t index = 0)
                : current_(ov.obj_->array), end_(ov.obj_->array + ov.size())
            {
                if (index >= ov.size()) {
                    current_ = end_;
                } else {
                    current_ += index;
                }
            }

            detail::object *current_{nullptr};
            detail::object *end_{nullptr};

            friend class map;
        };

        iterator begin() { return obj_ != nullptr ? iterator{*this} : iterator{}; }

        iterator end() { return obj_ != nullptr ? iterator{*this, size_unchecked()} : iterator{}; }

    protected:
        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        explicit map(const detail::object *underlying_object) : obj_(underlying_object) {}

        const detail::object *obj_{nullptr};

        friend class object_view;
    };

    template <typename T>
    [[nodiscard]] std::optional<T> as() const noexcept
        requires std::is_same_v<T, object_view::map>
    {
        if (type() != object_type::map) {
            [[unlikely]] return std::nullopt;
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

static_assert(sizeof(object_view) == sizeof(void *));

} // namespace ddwaf

namespace std {

template <> struct hash<ddwaf::object_view> {
    auto operator()(const ddwaf::object_view &obj) const
    {
        return std::hash<const void *>{}(static_cast<const void *>(obj.ptr()));
    }
};

} // namespace std
