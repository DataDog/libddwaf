// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "ddwaf.h"
#include "object_type.hpp"
#include "traits.hpp"
#include "utils.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace ddwaf {

namespace detail {

using object = ddwaf_object;

char *copy_string(const char *str, std::size_t len);
void realloc_array(object &obj);
void alloc_array(object &obj);

} // namespace detail

class owned_object;
class borrowed_object;
class object_view;
class object_key;

template <typename T> struct object_converter;

template <typename Derived> class readable_object {
public:
    // The API assumes that the caller has already verified that the method preconditions are met:
    //   - When using at, the accessed indexed is within bounds (using size*())
    //   - When using as, the accessed field matches the underlying object type (using is*())

    [[nodiscard]] std::size_t size() const noexcept
    {
        return static_cast<std::size_t>(static_cast<const Derived *>(this)->ref().nbEntries);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    [[nodiscard]] object_type type() const noexcept
    {
        return static_cast<object_type>(static_cast<const Derived *>(this)->ref().type);
    }

    [[nodiscard]] const char *data() const noexcept
    {
        return static_cast<const Derived *>(this)->ref().stringValue;
    }
    // The is_* methods can be used to check for collections of types
    [[nodiscard]] bool is_container() const noexcept
    {
        return (type() & container_object_type) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept { return (type() & scalar_object_type) != 0; }

    [[nodiscard]] bool is_map() const noexcept { return type() == object_type::map; }
    [[nodiscard]] bool is_array() const noexcept { return type() == object_type::array; }
    [[nodiscard]] bool is_string() const noexcept { return type() == object_type::string; }

    [[nodiscard]] bool is_valid() const noexcept { return type() != object_type::invalid; }
    [[nodiscard]] bool is_invalid() const noexcept { return type() == object_type::invalid; }

    // Access the underlying value based on the required type
    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, Derived>
    {
        return *this;
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, bool>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return obj.boolean;
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_signed_v<T>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return static_cast<T>(obj.intValue);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return static_cast<T>(obj.uintValue);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, double>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return static_cast<T>(obj.f64);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return {obj.stringValue, size()};
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, const char *>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return obj.stringValue;
    }

    // Access the underlying value based on the required type or return a default
    // value otherwise.
    template <typename T> [[nodiscard]] T as_or_default(T default_value) const noexcept
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        if (!is_compatible_type<T>(static_cast<object_type>(obj.type))) {
            [[unlikely]] return default_value;
        }
        return as<T>();
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
        return is_compatible_type<T>(type());
    }

    // Overload for other unsigned integer types
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires(!std::is_same_v<T, uint64_t>) && std::is_integral_v<T> && std::is_unsigned_v<T> &&
                (!std::is_same_v<T, bool>)
    {
        using limits = std::numeric_limits<T>;
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return is_compatible_type<uint64_t>(type()) && obj.uintValue <= limits::max();
    }

    // Overload for other signed integer types
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires(!std::is_same_v<T, int64_t>) && std::is_integral_v<T> && std::is_signed_v<T>
    {
        using limits = std::numeric_limits<T>;
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return is_compatible_type<int64_t>(type()) && obj.intValue >= limits::min() &&
               obj.intValue <= limits::max();
    }

    // Convert the underlying type to the requested type, converters are defined
    // in the object_converter header
    template <typename T> T convert() const;

    [[nodiscard]] owned_object clone() const;

private:
    readable_object() = default;

    friend Derived;
};

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

class object_view final : public readable_object<object_view> {
public:
    // The default constructor results in a view without value
    object_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object &underlying_object) : obj_(&underlying_object) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const detail::object *underlying_object) : obj_(underlying_object) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const owned_object &ow);
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    object_view(const borrowed_object &ow);

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
            return has_value() && is_string() && as<std::string_view>() == other;
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
            return has_value() && (!is_string() || as<std::string_view>() != other);
        } else {
            // Assume unknown types aren't equal
            return true;
        }
    }

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

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

        explicit iterator(const detail::object *obj, uint16_t idx = 0)
            : obj_(obj->array), size_(static_cast<uint16_t>(obj->nbEntries)), index_(idx),
              type_(static_cast<object_type>(obj->type))
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

    [[nodiscard]] iterator begin() const
    {
        assert(obj_ != nullptr);
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{obj_};
    }

    [[nodiscard]] iterator end() const
    {
        assert(obj_ != nullptr);
        // This check guarantees that the object is a container and not null
        if (!is_container()) {
            [[unlikely]] return {};
        }
        return iterator{obj_, static_cast<uint16_t>(obj_->nbEntries)};
    }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object *obj_{nullptr};
};

static_assert(sizeof(object_view) == sizeof(void *));

template <typename Derived> class writable_object {
public:
    [[nodiscard]] borrowed_object at(std::size_t idx);

    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);

private:
    writable_object() = default;

    friend Derived;
};

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class borrowed_object final : public readable_object<borrowed_object>,
                              public writable_object<borrowed_object> {
public:
    // borrowed_object() = default;
    explicit borrowed_object(detail::object *obj) : obj_(obj)
    {
        if (obj_ == nullptr) {
            throw std::invalid_argument("null borrowed object");
        }
    }
    explicit borrowed_object(detail::object &obj) : obj_(&obj) {}

    explicit borrowed_object(owned_object &obj);

    [[nodiscard]] detail::object &ref() { return *obj_; }
    [[nodiscard]] const detail::object &ref() const { return *obj_; }
    [[nodiscard]] detail::object *ptr() { return obj_; }
    [[nodiscard]] const detail::object *ptr() const { return obj_; }

protected:
    detail::object *obj_;

    friend class owned_object;
    friend class object_view;
};

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class owned_object final : public readable_object<owned_object>,
                           public writable_object<owned_object> {
public:
    using size_type = decltype(detail::object::nbEntries);
    using length_type = decltype(detail::object::nbEntries);

    owned_object() = default;
    explicit owned_object(detail::object obj, ddwaf_object_free_fn free_fn = ddwaf_object_free)
        : obj_(obj), free_fn_(free_fn)
    {}

    ~owned_object()
    {
        if (free_fn_ != nullptr) {
            free_fn_(&obj_);
        }
    }

    owned_object(const owned_object &) = delete;
    owned_object &operator=(const owned_object &) = delete;

    owned_object(owned_object &&other) noexcept : obj_(other.obj_), free_fn_(other.free_fn_)
    {
        other.obj_ = detail::object{};
    }

    owned_object &operator=(owned_object &&other) noexcept
    {
        obj_ = other.obj_;
        free_fn_ = other.free_fn_;
        other.obj_ = detail::object{};
        return *this;
    }

    [[nodiscard]] detail::object &ref() { return obj_; }
    [[nodiscard]] const detail::object &ref() const { return obj_; }
    [[nodiscard]] detail::object *ptr() { return &obj_; }
    [[nodiscard]] const detail::object *ptr() const { return &obj_; }

    static owned_object make_null()
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .stringValue = nullptr,
            .nbEntries = 0,
            .type = DDWAF_OBJ_NULL}};
    }

    static owned_object make_boolean(bool value)
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .boolean = value,
            .nbEntries = 0,
            .type = DDWAF_OBJ_BOOL}};
    }

    static owned_object make_signed(int64_t value)
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .intValue = value,
            .nbEntries = 0,
            .type = DDWAF_OBJ_SIGNED}};
    }

    static owned_object make_unsigned(uint64_t value)
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .uintValue = value,
            .nbEntries = 0,
            .type = DDWAF_OBJ_UNSIGNED}};
    }

    static owned_object make_float(double value)
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .f64 = value,
            .nbEntries = 0,
            .type = DDWAF_OBJ_FLOAT}};
    }

    static owned_object make_string_nocopy(
        const char *str, std::size_t len, ddwaf_object_free_fn free_fn = ddwaf_object_free)
    {
        return owned_object{{.parameterName = nullptr,
                                .parameterNameLength = 0,
                                .stringValue = str,
                                .nbEntries = static_cast<uint64_t>(len),
                                .type = DDWAF_OBJ_STRING},
            free_fn};
    }

    template <typename T>
    static owned_object make_string_nocopy(T str, ddwaf_object_free_fn free_fn = ddwaf_object_free)
        requires std::is_same_v<T, std::string_view> || std::is_same_v<T, object_key>
    {
        return make_string_nocopy(str.data(), str.size(), free_fn);
    }

    static owned_object make_string(const char *str, std::size_t len)
    {
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .stringValue = detail::copy_string(str, len),
            .nbEntries = static_cast<uint64_t>(len),
            .type = DDWAF_OBJ_STRING}};
    }

    static owned_object make_string(std::string_view str)
    {
        if (str.empty()) {
            return make_string("", 0);
        }
        return make_string(str.data(), str.size());
    }

    static owned_object make_array()
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .array = nullptr,
            .nbEntries = 0,
            .type = DDWAF_OBJ_ARRAY}};
    }

    static owned_object make_map()
    {
        return owned_object{{.parameterName = nullptr,
            .parameterNameLength = 0,
            .array = nullptr,
            .nbEntries = 0,
            .type = DDWAF_OBJ_MAP}};
    }

    detail::object move()
    {
        detail::object copy = obj_;
        obj_ = detail::object{};
        return copy;
    }

protected:
    detail::object obj_{};
    ddwaf_object_free_fn free_fn_{ddwaf_object_free};

    friend class borrowed_object;
    friend class object_view;
};

inline object_view::object_view(const owned_object &ow) : obj_(&ow.obj_) {}
inline object_view::object_view(const borrowed_object &ow) : obj_(ow.obj_) {}
inline borrowed_object::borrowed_object(owned_object &obj) : obj_(obj.ptr()) {}

// Convert the underlying type to the requested type, converters are defined
// in the object_converter header
template <typename Derived> template <typename T> T readable_object<Derived>::convert() const
{
    return object_converter<T>{static_cast<const Derived *>(this)->ref()}();
}

template <> struct object_converter<std::string> {
    explicit object_converter(object_view view) : view(view) {}
    std::string operator()() const
    {
        switch (view.type()) {
        case object_type::string:
            return view.as<std::string>();
        case object_type::boolean:
            return ddwaf::to_string<std::string>(view.as<bool>());
        case object_type::uint64:
            return ddwaf::to_string<std::string>(view.as<uint64_t>());
        case object_type::int64:
            return ddwaf::to_string<std::string>(view.as<int64_t>());
        case object_type::float64:
            return ddwaf::to_string<std::string>(view.as<double>());
        default:
            break;
        }
        return {};
    }
    object_view view;
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
