// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cassert>
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

class object_view;

// Temporary abstraction
class object_key {
public:
    // The default constructor results in a view without value
    object_key() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_key(const detail::object *underlying_object) : obj_(underlying_object) {}

    ~object_key() = default;
    object_key(const object_key &) = default;
    object_key(object_key &&) = default;
    object_key &operator=(const object_key &) = default;
    object_key &operator=(object_key &&) = default;

    [[nodiscard]] const char * data() const noexcept {
        return obj_ != nullptr ? obj_->parameterName : nullptr;
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        if (obj_ == nullptr || obj_->parameterName == nullptr) {
            [[unlikely]] return 0;
        }
        return static_cast<std::size_t>(obj_->parameterNameLength);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    explicit operator std::string_view() const noexcept
    {
        if (obj_ == nullptr || obj_->parameterName == nullptr) {
            [[unlikely]] return {};
        }
        return {obj_->parameterName, static_cast<std::size_t>(obj_->parameterNameLength)};
    }

    template <typename T> bool operator==(const T &other) const
        requires (std::is_same_v<T, std::string_view> || std::is_same_v<T, object_key>)
    {
        auto s = size();
        return s == other.size() && memcmp(data(), other.data(), s) == 0;
    }

protected:
    const detail::object *obj_{nullptr};
};

class optional_object_view {
public:
    // The default constructor results in a view without value
    optional_object_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    optional_object_view(object_view view);
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    optional_object_view(const detail::object *underlying_object) : obj_(underlying_object) {}

    ~optional_object_view() = default;
    optional_object_view(const optional_object_view &) = default;
    optional_object_view(optional_object_view &&) = default;
    optional_object_view &operator=(const optional_object_view &) = default;
    optional_object_view &operator=(optional_object_view &&) = default;

    [[nodiscard]] const detail::object &ref() const noexcept { return *obj_; }
    [[nodiscard]] const detail::object *ptr() const noexcept { return obj_; }

    template <typename T> bool operator==(const T &other) const
    {
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return ptr() == nullptr;
        } else if constexpr (std::is_same_v<T, ddwaf_object *>) {
            return ptr() == other;
        } else {
            return ptr() == other.ptr();
        }
    }
    template <typename T> bool operator!=(const T &other) const
    {
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return ptr() != nullptr;
        } else if constexpr (std::is_same_v<T, ddwaf_object *>) {
            return ptr() != other;
        } else {
            return ptr() != other.ptr();
        }
    }

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    [[nodiscard]] object_type type() const noexcept
    {
        assert(obj_ != nullptr);
        return static_cast<object_type>(obj_->type);
    }

    // These is_* methods provide further checks for consistency, albeit these
    // perhaps should be replaced by assertions.
    [[nodiscard]] bool is_container() const noexcept
    {
        assert(obj_ != nullptr);
        return (type() & container_object_type) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept
    {
        assert(obj_ != nullptr);
        return (type() & scalar_object_type) != 0;
    }

    // This method should only be called if the presence of a value has been
    // checked by using has_value();
    [[nodiscard]] object_view operator->() const noexcept;

    [[nodiscard]] object_view value() const noexcept;

protected:
    const detail::object *obj_{nullptr};
};

class object_view {
public:
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object &underlying_object) : obj_(underlying_object) {}

    ~object_view() = default;
    object_view(const object_view &) = default;
    object_view(object_view &&) = default;
    object_view &operator=(const object_view &) = delete;
    object_view &operator=(object_view &&) = delete;

    [[nodiscard]] const detail::object *ptr() const noexcept { return &obj_; }
    [[nodiscard]] const detail::object &ref() const noexcept { return obj_; }

    template <typename T> bool operator==(const T &other) const
    {
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return false;
        } else if constexpr (std::is_same_v<T, ddwaf_object *>) {
            return ptr() == other;
        } else {
            return ptr() == other.ptr();
        }
    }
    template <typename T> bool operator!=(const T &other) const
    {
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return true;
        } else if constexpr (std::is_same_v<T, ddwaf_object *>) {
            return ptr() != other;
        } else {
            return ptr() != other.ptr();
        }
    }

    [[nodiscard]] object_type type() const noexcept { return static_cast<object_type>(obj_.type); }

    [[nodiscard]] std::size_t size() const noexcept
    {
        return static_cast<std::size_t>(obj_.nbEntries);
    }

    [[nodiscard]] bool empty() const noexcept { return obj_.nbEntries == 0; }

    // These is_* methods provide further checks for consistency, albeit these
    // perhaps should be replaced by assertions.
    [[nodiscard]] bool is_container() const noexcept
    {
        return (type() & container_object_type) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept { return (type() & scalar_object_type) != 0; }

    // is<T> check whether the underlying type is compatible with the required
    // type. When it comes to numeric types, the request type must match the
    // one used within ddwaf_object, i.e. the type will not be cast to one of
    // a smaller size.
    template <typename T> [[nodiscard]] bool is() const noexcept
    {
        return is_compatible_type<T>(type());
    }

    // The unchecked API assumes that the caller has already verified that the
    // method preconditions are met:
    //   - When using at, the accessed indexed is within bounds (using size*())
    //   - When using as, the accessed field matches the underlying object type (using is*())
    //
    // The checked API (without suffix), always validates preconditions so it is
    // safer but introduces small overheads.

    // Access the key and value at index. If the container is an array, the key
    // will be an empty string.
    [[nodiscard]] std::pair<object_key, object_view> at_unchecked(std::size_t index) const noexcept
    {
        assert(index < size() && obj_.array != nullptr);

        const auto &slot = obj_.array[index];
        return {&slot, slot};
    }

    [[nodiscard]] std::pair<object_key, optional_object_view> at(std::size_t index) const noexcept
    {
        if (!is_container() || index > size()) {
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
        return obj_.boolean;
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, int64_t>
    {
        return static_cast<T>(obj_.intValue);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, uint64_t>
    {
        return static_cast<T>(obj_.uintValue);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, double>
    {
        return static_cast<T>(obj_.f64);
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        return {obj_.stringValue, size()};
    }

    template <typename T>
    [[nodiscard]] T as_unchecked() const noexcept
        requires std::is_same_v<T, const char *>
    {
        return obj_.stringValue;
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

        [[nodiscard]] object_key key() const
        {
            assert(obj_ != nullptr && obj_->array != nullptr && index_ < size_);

            return &obj_->array[index_];
        }

        [[nodiscard]] object_view value() const
        {
            assert(obj_ != nullptr && obj_->array != nullptr && index_ < size_);

            return obj_->array[index_];
        }

        std::pair<object_key, object_view> operator*() const
        {
            assert(obj_ != nullptr && obj_->array != nullptr && index_ < size_);

            auto &slot = obj_->array[index_];
            return {&slot, slot};
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
        return iterator{&obj_, limits};
    }

    iterator end()
    {
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{&obj_, {}, static_cast<uint16_t>(obj_.nbEntries)};
    }

    [[nodiscard]] const object_view *operator->() const noexcept { return this; }
    [[nodiscard]] object_view *operator->() noexcept { return this; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object &obj_;
};

static_assert(sizeof(object_view) == sizeof(void *));

inline optional_object_view::optional_object_view(object_view view) : obj_(view.ptr()) {}

inline object_view optional_object_view::operator->() const noexcept { return *obj_; }

inline object_view optional_object_view::value() const noexcept
{
    assert(obj_ != nullptr);
    return *obj_;
}
} // namespace ddwaf

namespace std {

template <> struct hash<ddwaf::object_view> {
    auto operator()(const ddwaf::object_view &obj) const
    {
        return std::hash<const void *>{}(static_cast<const void *>(obj.ptr()));
    }
};

} // namespace std
