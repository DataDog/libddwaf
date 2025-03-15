// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstring>
#include <list>
#include <string_view>
#include <type_traits>

#include "object.hpp"
#include "object_type.hpp"
#include "traits.hpp"
#include "utils.hpp"

namespace ddwaf {

template <typename T> struct object_converter;

class object_view;

// Temporary abstraction, this will be removed once the keys and values are
// split within ddwaf_object.
class object_key {
public:
    // The default constructor results in a key without value
    object_key() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_key(detail::object *underlying_object) : obj_(underlying_object) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_key(const detail::object *underlying_object) : obj_(underlying_object) {}

    ~object_key() = default;
    object_key(const object_key &) = default;
    object_key(object_key &&) = default;
    object_key &operator=(const object_key &) = default;
    object_key &operator=(object_key &&) = default;

    [[nodiscard]] const char *data() const noexcept
    {
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

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        if (obj_ == nullptr || obj_->parameterName == nullptr) {
            [[unlikely]] return {};
        }
        return {obj_->parameterName, static_cast<std::size_t>(obj_->parameterNameLength)};
    }

    template <typename T>
    bool operator==(const T &other) const
        requires(std::is_same_v<T, std::string_view> || std::is_same_v<T, object_key>)
    {
        auto s = size();
        return s == other.size() && memcmp(data(), other.data(), s) == 0;
    }

protected:
    const detail::object *obj_{nullptr};
};

class object_view {
public:
    // The default constructor results in a view without value
    object_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object &underlying_object) : obj_(&underlying_object) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object *underlying_object) : obj_(underlying_object) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const owned_object &ow) : obj_(&ow.obj_) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const borrowed_object &ow) : obj_(ow.obj_) {}

    ~object_view() = default;
    object_view(const object_view &) = default;
    object_view(object_view &&) = default;
    object_view &operator=(const object_view &) = default;
    object_view &operator=(object_view &&) = default;

    [[nodiscard]] const detail::object *ptr() const noexcept { return obj_; }
    [[nodiscard]] const detail::object &ref() const noexcept
    {
        assert(obj_ != nullptr);
        return *obj_;
    }

    template <typename T> bool operator==(const T &other) const
    {
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return ptr() == nullptr;
        } else if constexpr (std::is_same_v<std::decay_t<T>, ddwaf_object *>) {
            return ptr() == other;
        } else if constexpr (std::is_same_v<std::decay_t<T>, ddwaf_object>) {
            return ptr() == &other;
        } else if constexpr (std::is_same_v<std::decay_t<T>, object_view>) {
            return ptr() == other.ptr();
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string_view>) {
            return has_value() && is<std::string_view>() && as<std::string_view>() == other;
        } else {
            // Assume unknown types aren't equal
            return false;
        }
    }
    template <typename T> bool operator!=(const T &other) const
    {
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            return ptr() != nullptr;
        } else if constexpr (std::is_same_v<std::decay_t<T>, ddwaf_object *>) {
            return ptr() != other;
        } else if constexpr (std::is_same_v<std::decay_t<T>, ddwaf_object>) {
            return ptr() != &other;
        } else if constexpr (std::is_same_v<std::decay_t<T>, object_view>) {
            return ptr() != other.ptr();
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string_view>) {
            return has_value() && (!is<std::string_view>() || as<std::string_view>() != other);
        } else {
            // Assume unknown types aren't equal
            return true;
        }
    }

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    [[nodiscard]] object_type type() const noexcept
    {
        assert(obj_ != nullptr);
        return static_cast<object_type>(obj_->type);
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        assert(obj_ != nullptr);
        return static_cast<std::size_t>(obj_->nbEntries);
    }

    [[nodiscard]] bool empty() const noexcept
    {
        assert(obj_ != nullptr);
        return obj_->nbEntries == 0;
    }

    [[nodiscard]] const char *data() const noexcept
    {
        assert(obj_ != nullptr);
        return obj_->stringValue;
    }

    // The is_* methods can be used to check for collections of types
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

    [[nodiscard]] bool is_map() const noexcept
    {
        assert(obj_ != nullptr);
        return type() == object_type::map;
    }

    [[nodiscard]] bool is_array() const noexcept
    {
        assert(obj_ != nullptr);
        return type() == object_type::array;
    }

    // is<T> checks whether the underlying type is compatible with the required
    // type. When it comes to numeric types, the request type must match the
    // one used within ddwaf_object, i.e. the type will not be cast to one of
    // a smaller size.
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires is_type_in_set_v<T, bool, int64_t, uint64_t, double, std::string, std::string_view,
            const char *>
    {
        assert(obj_ != nullptr);
        return is_compatible_type<T>(type());
    }

    // Overload for other unsigned integer types
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires(!std::is_same_v<T, uint64_t>) && std::is_integral_v<T> && std::is_unsigned_v<T> &&
                (!std::is_same_v<T, bool>)
    {
        assert(obj_ != nullptr);
        using limits = std::numeric_limits<T>;
        return is_compatible_type<uint64_t>(type()) && obj_->uintValue <= limits::max();
    }

    // Overload for other signed integer types
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires(!std::is_same_v<T, int64_t>) && std::is_integral_v<T> && std::is_signed_v<T>
    {
        assert(obj_ != nullptr);
        using limits = std::numeric_limits<T>;
        return is_compatible_type<int64_t>(type()) && obj_->intValue >= limits::min() &&
               obj_->intValue <= limits::max();
    }

    // The API assumes that the caller has already verified that the method preconditions are met:
    //   - When using at, the accessed indexed is within bounds (using size*())
    //   - When using as, the accessed field matches the underlying object type (using is*())

    // Access the key and value at index. If the container is an array, the key
    // will be an empty string.
    [[nodiscard]] std::pair<object_key, object_view> at(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size() && obj_->array != nullptr);

        const auto &slot = obj_->array[index];
        if (type() == object_type::map) {
            return {&slot, slot};
        }
        return {{}, slot};
    }

    // Access the key at index. If the container is an array, the key will be an empty string.
    [[nodiscard]] object_key at_key(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size() && obj_->array != nullptr);
        if (type() == object_type::map) {
            return &obj_->array[index];
        }
        return {};
    }

    // Access the value at index.
    [[nodiscard]] object_view at_value(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size() && obj_->array != nullptr);
        return obj_->array[index];
    }

    // Access the underlying value based on the required type
    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, object_view>
    {
        assert(obj_ != nullptr);
        return {obj_};
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, bool>
    {
        assert(obj_ != nullptr);
        return obj_->boolean;
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_signed_v<T>
    {
        assert(obj_ != nullptr);
        return static_cast<T>(obj_->intValue);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
    {
        assert(obj_ != nullptr);
        return static_cast<T>(obj_->uintValue);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, double>
    {
        assert(obj_ != nullptr);
        return static_cast<T>(obj_->f64);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        assert(obj_ != nullptr);
        return {obj_->stringValue, size()};
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, const char *>
    {
        assert(obj_ != nullptr);
        return obj_->stringValue;
    }

    // Access the underlying value based on the required type or return a default
    // value otherwise.
    template <typename T> [[nodiscard]] T as_or_default(T default_value) const noexcept
    {
        assert(obj_ != nullptr);
        if (!is_compatible_type<T>(type())) {
            [[unlikely]] return default_value;
        }
        return as<T>();
    }

    // Convert the underlying type to the requested type, converters are defined
    // in the object_converter header
    template <typename T> T convert() const { return object_converter<T>{*this}(); }

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
            assert(obj_ != nullptr && index_ < size_);
            if (type_ == object_type::map) {
                return &obj_[index_];
            }
            return {};
        }

        [[nodiscard]] object_view value() const
        {
            assert(obj_ != nullptr && index_ < size_);
            return obj_[index_];
        }

        std::pair<object_key, object_view> operator*() const
        {
            assert(obj_ != nullptr && index_ < size_);
            const auto &slot = obj_[index_];
            if (type_ == object_type::map) {
                return {&slot, slot};
            }
            return {{}, slot};
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
            : obj_(obj->array), size_(std::min(static_cast<uint16_t>(limits.max_container_size),
                                    static_cast<uint16_t>(obj->nbEntries))),
              index_(idx), type_(static_cast<object_type>(obj->type))
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

    [[nodiscard]] iterator begin(const object_limits &limits = {}) const
    {
        assert(obj_ != nullptr);
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{obj_, limits};
    }

    [[nodiscard]] iterator end() const
    {
        assert(obj_ != nullptr);
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{obj_, {}, static_cast<uint16_t>(obj_->nbEntries)};
    }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object *obj_{nullptr};
};

static_assert(sizeof(object_view) == sizeof(void *));

inline owned_object clone(object_view input)
{
    auto clone_helper = [](object_view source) -> owned_object {
        switch (source.type()) {
        case object_type::boolean:
            return owned_object::make_boolean(source.as<bool>());
        case object_type::string:
            return owned_object::make_string(source.as<std::string_view>());
        case object_type::int64:
            return owned_object::make_signed(source.as<int64_t>());
        case object_type::uint64:
            return owned_object::make_unsigned(source.as<uint64_t>());
        case object_type::float64:
            return owned_object::make_float(source.as<double>());
        case object_type::null:
            return owned_object::make_null();
        case object_type::map:
            return owned_object::make_map();
        case object_type::array:
            return owned_object::make_array();
        case object_type::invalid:
            break;
        }
        return {};
    };

    std::list<std::pair<object_view, borrowed_object>> queue;

    auto copy = clone_helper(input);
    if (input.is_container()) {
        queue.emplace_front(input, copy);
    }

    while (!queue.empty()) {
        auto &[source, destination] = queue.front();
        for (uint64_t i = 0; i < source.size(); ++i) {
            const auto &[key, value] = source.at(i);
            if (source.type() == object_type::map) {
                destination.emplace(key.as<std::string_view>(), clone_helper(value));
            } else if (source.type() == object_type::array) {
                destination.emplace_back(clone_helper(value));
            }
        }

        for (uint64_t i = 0; i < source.size(); ++i) {
            auto child = source.at_value(i);
            if (child.is_container()) {
                queue.emplace_back(child, destination.at(i));
            }
        }

        queue.pop_front();
    }

    return copy;
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
