// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "dynamic_string.hpp"
#include "object_type.hpp"
#include "traits.hpp"
#include "utils.hpp"

#include <cassert>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <stdexcept>
#include <type_traits>

namespace ddwaf {

namespace detail {

union object;
struct object_kv;

constexpr std::size_t small_string_size = 14;

struct object_bool {
    object_type type;
    bool val;
};

struct object_signed {
    object_type type;
    int64_t val;
};

struct object_unsigned {
    object_type type;
    uint64_t val;
};

struct object_float {
    object_type type;
    double val;
};

struct object_string {
    object_type type;
    uint16_t size;
    uint16_t capacity;
    char *ptr;
};

struct object_small_string {
    object_type type;
    uint8_t size;
    std::array<char, small_string_size> data;
};

struct object_const_string {
    object_type type;
    uint32_t size;
    const char *ptr;
};

struct object_long_string {
    object_type type;
    uint32_t size;
    char *ptr;
};

struct object_array {
    object_type type;
    uint16_t size;
    uint16_t capacity;
    object *ptr;
};

struct object_map {
    object_type type;
    uint16_t size;
    uint16_t capacity;
    object_kv *ptr;
};

union [[gnu::may_alias]] object {
    object_type type;
    union {
        object_bool b8;
        object_signed i64;
        object_unsigned u64;
        object_float f64;
        object_string str;
        object_small_string sstr;
        object_long_string lstr;
        object_const_string cstr;
        object_array array;
        object_map map;
    } via;
};

struct object_kv {
    object key;
    object val;
};

static_assert(sizeof(object) == 16);
static_assert(sizeof(object_kv) == 32);

static_assert(std::is_standard_layout_v<object>);
static_assert(std::is_standard_layout_v<object_kv>);

static_assert(std::is_trivial_v<object>);
static_assert(std::is_trivial_v<object_kv>);

static_assert(offsetof(object_string, ptr) == offsetof(object_long_string, ptr));
static_assert(offsetof(object_string, ptr) == offsetof(object_const_string, ptr));

static_assert(offsetof(object_string, size) == offsetof(object_map, size));
static_assert(offsetof(object_string, size) == offsetof(object_array, size));

static_assert(offsetof(object_string, capacity) == offsetof(object_map, capacity));
static_assert(offsetof(object_string, capacity) == offsetof(object_array, capacity));

using object_free_fn = void (*)(object *object);

template <typename T> constexpr std::size_t maxof_v = std::numeric_limits<T>::max();

template <typename SizeType> inline char *copy_string(const char *str, SizeType length)
{
    // TODO new char[size];
    if (length == maxof_v<SizeType>) {
        throw std::bad_alloc();
    }

    // NOLINTNEXTLINE(hicpp-no-malloc)
    char *copy = static_cast<char *>(malloc(length + 1));
    if (copy == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }

    memcpy(copy, str, length);
    copy[length] = '\0';

    return copy;
}

template <typename T, typename SizeType> T *alloc_helper(SizeType size)
{
    // NOLINTNEXTLINE(hicpp-no-malloc)
    auto *data = static_cast<T *>(calloc(size, sizeof(T)));
    if (size > 0 && data == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }
    return data;
}

template <typename T, typename SizeType>
inline std::pair<T *, SizeType> realloc_helper(T *data, SizeType size)
{
    // Since allocators have no realloc interface, we're just using calloc
    // as it'll be equivalent once allocators are supported
    SizeType new_size;
    if (size > maxof_v<SizeType> / 2) [[unlikely]] {
        new_size = maxof_v<SizeType>;
    } else {
        new_size = size * 2;
    }

    // NOLINTNEXTLINE(hicpp-no-malloc)
    auto *new_data = static_cast<T *>(calloc(new_size, sizeof(T)));
    if (new_data == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }

    memcpy(new_data, data, sizeof(T) * size);
    // NOLINTNEXTLINE(hicpp-no-malloc)
    free(data);

    return {new_data, new_size};
}

// NOLINTNEXTLINE(misc-no-recursion)
inline void object_destroy(object &obj)
{
    if (obj.type == object_type::array) {
        for (std::size_t i = 0; i < obj.via.array.size; ++i) {
            object_destroy(obj.via.array.ptr[i]);
        }
        // NOLINTNEXTLINE(hicpp-no-malloc)
        free(obj.via.array.ptr);
    } else if (obj.type == object_type::map) {
        for (std::size_t i = 0; i < obj.via.map.size; ++i) {
            object_destroy(obj.via.map.ptr[i].key);
            object_destroy(obj.via.map.ptr[i].val);
        }
        // NOLINTNEXTLINE(hicpp-no-malloc)
        free(obj.via.map.ptr);
    } else if (obj.type == object_type::string) {
        // NOLINTNEXTLINE(hicpp-no-malloc)
        free(obj.via.str.ptr);
    } else if (obj.type == object_type::long_string) {
        // NOLINTNEXTLINE(hicpp-no-malloc)
        free(obj.via.lstr.ptr);
    }
}

inline void object_free(detail::object *ptr) { object_destroy(*ptr); }

namespace initializer {

struct movable_object;
using key_value = std::pair<std::string_view, movable_object>;

} // namespace initializer

} // namespace detail

class owned_object;
class borrowed_object;
class object_view;

template <typename T> struct object_converter;

template <typename Derived> class readable_object {
public:
    // The API assumes that the caller has already verified that the method preconditions are met:
    //   - When using at, the accessed indexed is within bounds (using size*())
    //   - When using as, the accessed field matches the underlying object type (using is*())

    [[nodiscard]] std::size_t size() const noexcept
    {
        const auto t = type();
        if (t == object_type::small_string) {
            return static_cast<std::size_t>(
                static_cast<const Derived *>(this)->ref().via.sstr.size);
        }
        if (t == object_type::const_string || t == object_type::long_string) {
            return static_cast<std::size_t>(
                static_cast<const Derived *>(this)->ref().via.cstr.size);
        }
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
        return static_cast<std::size_t>(static_cast<const Derived *>(this)->ref().via.str.size);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    [[nodiscard]] object_type type() const noexcept
    {
        return static_cast<object_type>(static_cast<const Derived *>(this)->ref().type);
    }

    [[nodiscard]] const char *data() const noexcept
    {
        if (type() == object_type::small_string) {
            return static_cast<const Derived *>(this)->ref().via.sstr.data.data();
        }
        return static_cast<const Derived *>(this)->ref().via.str.ptr;
    }
    // The is_* methods can be used to check for collections of types
    [[nodiscard]] bool is_container() const noexcept
    {
        return (type() & object_type::container) != 0;
    }
    [[nodiscard]] bool is_scalar() const noexcept { return (type() & object_type::scalar) != 0; }

    [[nodiscard]] bool is_map() const noexcept { return type() == object_type::map; }
    [[nodiscard]] bool is_array() const noexcept { return type() == object_type::array; }
    [[nodiscard]] bool is_string() const noexcept { return (type() & object_type::string) != 0; }

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
        return obj.via.b8.val;
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_signed_v<T>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return static_cast<T>(obj.via.i64.val);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return static_cast<T>(obj.via.u64.val);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, double>
    {
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return static_cast<T>(obj.via.f64.val);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        return {data(), size()};
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, const char *>
    {
        return data();
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
        return is_compatible_type<uint64_t>(type()) && obj.via.u64.val <= limits::max();
    }

    // Overload for other signed integer types
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires(!std::is_same_v<T, int64_t>) && std::is_integral_v<T> && std::is_signed_v<T>
    {
        using limits = std::numeric_limits<T>;
        const auto &obj = static_cast<const Derived *>(this)->ref();
        return is_compatible_type<int64_t>(type()) && obj.via.i64.val >= limits::min() &&
               obj.via.i64.val <= limits::max();
    }

    // Convert the underlying type to the requested type
    template <typename T> T convert() const;

    [[nodiscard]] owned_object clone() const;

private:
    readable_object() = default;

    friend Derived;
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

    object_view(owned_object &&ow) = delete;

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
        if constexpr (std::is_same_v<std::decay_t<T>, object_view>) {
            return ptr() == other.ptr();
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string_view>) {
            return has_value() && is_string() && as<std::string_view>() == other;
        } else {
            static_assert(!std::is_same_v<T, T>, "unsupported type for object_view::operator==");
        }
    }
    template <typename T> bool operator!=(const T &other) const
    {
        if constexpr (std::is_same_v<std::decay_t<T>, object_view>) {
            return ptr() != other.ptr();
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string_view>) {
            return has_value() && (!is_string() || as<std::string_view>() != other);
        } else {
            static_assert(!std::is_same_v<T, T>, "unsupported type for object_view::operator!=");
        }
    }

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    // Access the key and value at index. If the container is an array, the key
    // will be an empty string.
    [[nodiscard]] std::pair<object_view, object_view> at(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size());
        if (type() == object_type::map) {
            assert(obj_->via.map.ptr != nullptr);
            const auto &slot = obj_->via.map.ptr[index];
            return {slot.key, slot.val};
        }
        assert(obj_->via.array.ptr != nullptr);
        return {{}, obj_->via.array.ptr[index]};
    }

    // Access the key at index. If the container is an array, the key will be an empty string.
    [[nodiscard]] object_view at_key(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size());
        if (type() == object_type::map) {
            assert(obj_->via.map.ptr != nullptr);
            return obj_->via.map.ptr[index].key;
        }
        assert(obj_->via.array.ptr != nullptr);
        return {};
    }

    // Access the value at index.
    [[nodiscard]] object_view at_value(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size());
        if (type() == object_type::map) {
            assert(obj_->via.map.ptr != nullptr);
            return obj_->via.map.ptr[index].val;
        }
        assert(obj_->via.array.ptr != nullptr);
        return obj_->via.array.ptr[index];
    }

    [[nodiscard]] object_view find(std::string_view expected_key) const noexcept
    {
        assert(obj_ != nullptr && type() == object_type::map && obj_->via.map.ptr != nullptr);

        for (std::size_t i = 0; i < size(); ++i) {
            auto [key, value] = at(i);

            if (expected_key == key.as<std::string_view>()) {
                return value;
            }
        }
        return {};
    }

    object_view find_key_path(std::span<const std::string> key_path)
    {
        auto root = *this;
        auto current = root;
        for (auto it = key_path.begin(); current.has_value() && it != key_path.end(); ++it) {
            root = current;
            if (!root.is_map()) {
                return {};
            }

            current = {};
            for (std::size_t i = 0; i < root.size(); ++i) {
                const auto &[key, child] = root.at(i);

                auto child_key = key.as<std::string_view>();
                if (*it == child_key) {
                    current = child;
                    break;
                }
            }
        }
        return current;
    }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object *obj_{nullptr};
};

static_assert(sizeof(object_view) == sizeof(void *));

template <typename Derived> class writable_object {
public:
    [[nodiscard]] borrowed_object at(std::size_t idx);

    // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);
    // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
    borrowed_object emplace(owned_object &&key, owned_object &&value);

    template <typename T> borrowed_object emplace_back(T &&value);

    template <typename T> borrowed_object emplace(std::string_view key, T &&value);

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
    borrowed_object &operator=(owned_object &&obj);

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
    owned_object() = default;
    explicit owned_object(detail::object obj, detail::object_free_fn free_fn = detail::object_free)
        : obj_(obj), free_fn_(free_fn)
    {}

    explicit owned_object(std::nullptr_t) { *this = make_null(); }
    explicit owned_object(bool value) { *this = make_boolean(value); }

    template <typename T>
    explicit owned_object(T value)
        requires std::is_integral_v<T> && std::is_signed_v<T>
    {
        *this = make_signed(value);
    }

    template <typename T>
    explicit owned_object(T value)
        requires(!std::is_same_v<T, bool>) && std::is_unsigned_v<T>
    {
        *this = make_unsigned(value);
    }

    template <typename T>
    explicit owned_object(T value)
        requires std::is_floating_point_v<T>
    {
        *this = make_float(value);
    }

    template <typename T>
    explicit owned_object(T value)
        requires is_type_in_set_v<T, std::string, std::string_view, const char *, dynamic_string>
    {
        *this = make_string(std::string_view{value});
    }

    explicit owned_object(const char *data, std::size_t size) { *this = make_string(data, size); }

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
        if (free_fn_ != nullptr) {
            free_fn_(&obj_);
        }

        obj_ = other.obj_;
        free_fn_ = other.free_fn_;
        other.obj_ = detail::object{};
        other.free_fn_ = nullptr;
        return *this;
    }

    [[nodiscard]] detail::object &ref() { return obj_; }
    [[nodiscard]] const detail::object &ref() const { return obj_; }
    [[nodiscard]] detail::object *ptr() { return &obj_; }
    [[nodiscard]] const detail::object *ptr() const { return &obj_; }

    static owned_object make_null() { return owned_object{{.type = object_type::null}}; }

    static owned_object make_boolean(bool value)
    {
        return owned_object{{.via{.b8{.type = object_type::boolean, .val = value}}}};
    }

    static owned_object make_signed(int64_t value)
    {
        return owned_object{{.via{.i64{.type = object_type::int64, .val = value}}}};
    }

    static owned_object make_unsigned(uint64_t value)
    {
        return owned_object{{.via{.u64{.type = object_type::uint64, .val = value}}}};
    }

    static owned_object make_float(double value)
    {
        return owned_object{{.via{.f64{.type = object_type::float64, .val = value}}}};
    }

    static owned_object make_string_nocopy(
        const char *str, std::size_t len, detail::object_free_fn free_fn = detail::object_free)
    {
        return owned_object{{.via{.lstr{.type = object_type::long_string,
                                .size = static_cast<uint16_t>(len),
                                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                .ptr = const_cast<char *>(str)}}},
            free_fn};
    }

    template <typename T>
    static owned_object make_string_nocopy(
        T str, detail::object_free_fn free_fn = detail::object_free)
        requires std::is_same_v<T, std::string_view> || std::is_same_v<T, object_view>
    {
        return make_string_nocopy(str.data(), str.size(), free_fn);
    }

    static owned_object make_string(const char *str, std::size_t len)
    {
        if (len < detail::small_string_size) {
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            owned_object obj{{.via{.sstr{.type = object_type::small_string,
                                 .size = static_cast<uint8_t>(len),
                                 .data = {}}}},
                detail::object_free};
            memcpy(obj.obj_.via.sstr.data.data(), str, len);
            // TODO avoid nul terminator
            obj.obj_.via.sstr.data[len] = '\0';
            return obj;
        }

        if (len >= detail::maxof_v<decltype(detail::object_string::size)>) {
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            return owned_object{{.via{.lstr{.type = object_type::long_string,
                                    .size = static_cast<uint16_t>(len),
                                    .ptr = detail::copy_string(str, len)}}},
                detail::object_free};
        }
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        return owned_object{{.via{.str{.type = object_type::string,
                                .size = static_cast<uint16_t>(len),
                                .capacity = static_cast<uint16_t>(len),
                                .ptr = detail::copy_string(str, len)}}},
            detail::object_free};
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
        return owned_object{
            {.via{.array{.type = object_type::array, .size = 0, .capacity = 0, .ptr = nullptr}}},
            detail::object_free};
    }

    static owned_object make_map()
    {
        return owned_object{
            {.via{.map{.type = object_type::map, .size = 0, .capacity = 0, .ptr = nullptr}}},
            detail::object_free};
    }

    static owned_object make_array(std::initializer_list<detail::initializer::movable_object> list);
    static owned_object make_map(std::initializer_list<detail::initializer::key_value> list);

    detail::object move()
    {
        detail::object copy = obj_;
        obj_ = detail::object{};
        free_fn_ = nullptr;
        return copy;
    }

protected:
    detail::object obj_{.type = object_type::invalid};
    detail::object_free_fn free_fn_{nullptr};

    friend class borrowed_object;
    friend class object_view;
};

namespace detail::initializer {

struct movable_object {
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    template <typename T> movable_object(T &&value) : object{std::forward<T>(value)} {}
    movable_object(const movable_object &) = delete;
    movable_object(movable_object &&) = delete;
    movable_object operator=(const movable_object &) = delete;
    movable_object operator=(movable_object &&) = delete;
    ~movable_object() = default;
    mutable owned_object object;
};

} // namespace detail::initializer

inline object_view::object_view(const owned_object &ow) : obj_(&ow.obj_) {}
inline object_view::object_view(const borrowed_object &ow) : obj_(ow.obj_) {}

// Convert the underlying type to the requested type, converters are defined
// in the object_converter header
template <typename Derived> template <typename T> T readable_object<Derived>::convert() const
{
    return object_converter<T>{static_cast<const Derived *>(this)->ref()}();
}

template <typename Derived> [[nodiscard]] owned_object readable_object<Derived>::clone() const
{
    auto clone_helper = [](object_view source) -> owned_object {
        switch (source.type()) {
        case object_type::boolean:
            return owned_object::make_boolean(source.as<bool>());
        case object_type::string:
        case object_type::small_string:
        case object_type::long_string:
            return owned_object::make_string(source.as<std::string_view>());
        case object_type::const_string:
            return owned_object::make_string_nocopy(source.data(), source.size());
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
        default:
            break;
        }
        return {};
    };

    std::deque<std::pair<object_view, borrowed_object>> queue;

    const object_view input = static_cast<const Derived *>(this)->ref();
    auto copy = clone_helper(input);
    if (copy.is_container()) {
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

template <> struct object_converter<std::string> {
    explicit object_converter(object_view view) : view(view) {}
    std::string operator()() const
    {
        switch (view.type()) {
        case object_type::string:
        case object_type::const_string:
        case object_type::small_string:
        case object_type::long_string:
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

template <typename Derived>
[[nodiscard]] borrowed_object writable_object<Derived>::at(std::size_t idx)
{
    auto &container = static_cast<const Derived *>(this)->ref();

    assert((static_cast<object_type>(container.type) & object_type::container) != 0);

    if (container.type == object_type::map) {
        assert(idx < static_cast<std::size_t>(container.via.map.size));
        return borrowed_object{&container.via.map.ptr[idx].val};
    }

    assert(idx < static_cast<std::size_t>(container.via.array.size));
    return borrowed_object{&container.via.array.ptr[idx]};
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object writable_object<Derived>::emplace_back(owned_object &&value)
{
    auto &container = static_cast<Derived *>(this)->ref();

    assert(static_cast<object_type>(container.type) == object_type::array);

    // We preallocate 8 entries
    if (container.via.array.size == 0) {
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.array.ptr = detail::alloc_helper<detail::object>(8);
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.array.capacity = 8;
    } else if (container.via.array.capacity == container.via.array.size) {
        auto [new_array, new_capacity] =
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            detail::realloc_helper(container.via.array.ptr, container.via.array.capacity);
        container.via.array.ptr = new_array;
        container.via.array.capacity = new_capacity;
    }

    auto &slot = container.via.array.ptr[container.via.array.size++];
    slot = value.move();

    return borrowed_object{slot};
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object writable_object<Derived>::emplace(std::string_view key, owned_object &&value)
{
    return emplace(owned_object{key}, std::move(value));
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved,bugprone-easily-swappable-parameters)
borrowed_object writable_object<Derived>::emplace(owned_object &&key, owned_object &&value)
{
    auto &container = static_cast<Derived *>(this)->ref();
    assert(static_cast<object_type>(container.type) == object_type::map);

    // We preallocate 8 entries
    if (container.via.map.size == 0) {
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.map.ptr = detail::alloc_helper<detail::object_kv>(8);
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.map.capacity = 8;
    } else if (container.via.map.capacity == container.via.map.size) {
        auto [new_map, new_capacity] =
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            detail::realloc_helper(container.via.map.ptr, container.via.map.capacity);
        container.via.map.ptr = new_map;
        container.via.map.capacity = new_capacity;
    }

    auto &slot = container.via.map.ptr[container.via.map.size++];
    slot.key = key.move();
    slot.val = value.move();

    return borrowed_object{slot.val};
}

template <typename Derived>
template <typename T>
borrowed_object writable_object<Derived>::emplace_back(T &&value)
{
    return emplace_back(owned_object{std::forward<T>(value)});
}

template <typename Derived>
template <typename T>
borrowed_object writable_object<Derived>::emplace(std::string_view key, T &&value)
{
    return emplace(key, owned_object{std::forward<T>(value)});
}

inline borrowed_object::borrowed_object(owned_object &obj) : obj_(obj.ptr()) {}

// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
inline borrowed_object &borrowed_object::operator=(owned_object &&obj)
{
    ref() = obj.move();
    return *this;
}

inline owned_object owned_object::make_array(
    std::initializer_list<detail::initializer::movable_object> list)
{
    auto container = make_array();
    for (const auto &value : list) { container.emplace_back(std::move(value.object)); }
    return container;
}

inline owned_object owned_object::make_map(
    std::initializer_list<detail::initializer::key_value> list)
{
    auto container = make_map();
    for (const auto &[key, value] : list) { container.emplace(key, std::move(value.object)); }
    return container;
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
