// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "dynamic_string.hpp"
#include "memory_resource.hpp"
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

class object_view;
class map_view;
class array_view;

class owned_object;
class borrowed_object;

template <typename T> struct object_converter;

namespace detail {

union object;
struct object_kv;

constexpr std::size_t small_string_size = 14;

template <typename T> struct object_scalar {
    object_type type;
    T val;
};

struct object_string {
    object_type type;
    uint32_t size;
    char *ptr;
};

struct object_small_string {
    object_type type;
    uint8_t size;
    std::array<char, small_string_size> data;
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
    union [[gnu::packed]] {
        object_scalar<bool> b8;
        object_scalar<int64_t> i64;
        object_scalar<uint64_t> u64;
        object_scalar<double> f64;
        object_string str;
        object_small_string sstr;
        object_array array;
        object_map map;
    } via;

    object &operator=(owned_object &&o) noexcept;
};

struct object_kv {
    object key;
    object val;
};

static_assert(sizeof(object) == 16);
static_assert(sizeof(object_kv) == 32);

static_assert(std::is_standard_layout_v<object>);
static_assert(std::is_trivially_copyable_v<object>);
static_assert(std::is_trivially_default_constructible_v<object>);

static_assert(std::is_standard_layout_v<object_kv>);
static_assert(std::is_trivially_copyable_v<object_kv>);
static_assert(std::is_trivially_default_constructible_v<object_kv>);

static_assert(offsetof(object, type) == offsetof(object_scalar<bool>, type));
static_assert(offsetof(object, type) == offsetof(object_scalar<int64_t>, type));
static_assert(offsetof(object, type) == offsetof(object_scalar<uint64_t>, type));
static_assert(offsetof(object, type) == offsetof(object_scalar<double>, type));

static_assert(offsetof(object, type) == offsetof(object_string, type));
static_assert(offsetof(object, type) == offsetof(object_small_string, type));

static_assert(offsetof(object, type) == offsetof(object_array, type));
static_assert(offsetof(object, type) == offsetof(object_map, type));

static_assert(offsetof(object_map, size) == offsetof(object_array, size));
static_assert(offsetof(object_map, capacity) == offsetof(object_array, capacity));
static_assert(offsetof(object_map, ptr) == offsetof(object_array, ptr));

using object_free_fn = void (*)(object *object);

template <typename T> constexpr std::size_t maxof_v = std::numeric_limits<T>::max();

template <typename SizeType> inline char *copy_string(const char *str, SizeType length)
{
    if (length == maxof_v<SizeType>) {
        throw std::bad_alloc();
    }

    static std::pmr::memory_resource *alloc = std::pmr::get_default_resource();

    auto *copy = static_cast<char *>(alloc->allocate(length, alignof(char)));
    memcpy(copy, str, length);

    return copy;
}

template <typename T, typename SizeType>
T *alloc_helper(SizeType size)
    requires(std::is_unsigned_v<SizeType> && sizeof(SizeType) <= sizeof(std::size_t))

{
    static std::pmr::memory_resource *alloc = std::pmr::get_default_resource();
    // TODO add check for sizeof(T) * size
    return static_cast<T *>(alloc->allocate(sizeof(T) * size, alignof(T)));
}

template <typename T, typename SizeType>
inline std::pair<T *, SizeType> realloc_helper(T *data, SizeType size)
    requires(std::is_unsigned_v<SizeType> && sizeof(SizeType) <= sizeof(std::size_t))
{
    // Since allocators have no realloc interface, we're just using calloc
    // as it'll be equivalent once allocators are supported
    SizeType new_size;
    if (size > maxof_v<SizeType> / 2) [[unlikely]] {
        new_size = maxof_v<SizeType>;
    } else {
        new_size = size * 2;
    }

    static std::pmr::memory_resource *alloc = std::pmr::get_default_resource();

    auto *new_data = static_cast<T *>(alloc->allocate(sizeof(T) * new_size, alignof(T)));
    memcpy(new_data, data, sizeof(T) * size);

    alloc->deallocate(data, sizeof(T) * size, alignof(T));

    return {new_data, new_size};
}

// NOLINTNEXTLINE(misc-no-recursion)
inline void object_destroy(object &obj)
{
    static std::pmr::memory_resource *alloc = std::pmr::get_default_resource();

    if (obj.type == object_type::array) {
        for (std::size_t i = 0; i < obj.via.array.size; ++i) {
            object_destroy(obj.via.array.ptr[i]);
        }
        if (obj.via.array.ptr != nullptr) {
            alloc->deallocate(obj.via.array.ptr, sizeof(detail::object) * obj.via.array.capacity,
                alignof(detail::object));
        }
    } else if (obj.type == object_type::map) {
        for (std::size_t i = 0; i < obj.via.map.size; ++i) {
            object_destroy(obj.via.map.ptr[i].key);
            object_destroy(obj.via.map.ptr[i].val);
        }
        if (obj.via.map.ptr != nullptr) {
            alloc->deallocate(obj.via.map.ptr, sizeof(detail::object_kv) * obj.via.map.capacity,
                alignof(detail::object_kv));
        }
    } else if (obj.type == object_type::string) {
        if (obj.via.str.ptr != nullptr) {
            alloc->deallocate(obj.via.str.ptr, obj.via.str.size, alignof(char));
        }
    }
}

inline void object_free(detail::object *ptr) { object_destroy(*ptr); }

namespace initializer {

struct movable_object;
using key_value = std::pair<std::string_view, movable_object>;

} // namespace initializer

} // namespace detail

template <typename Derived> class readable_object {
public:
    // The API assumes that the caller has already verified that the method preconditions are met:
    //   - When using at, the accessed indexed is within bounds (using size*())
    //   - When using as, the accessed field matches the underlying object type (using is*())

    [[nodiscard]] std::size_t size() const noexcept
    {
        const auto t = type();
        if (t == object_type::small_string) {
            return static_cast<std::size_t>(object_ref().via.sstr.size);
        }

        if (t == object_type::string || t == object_type::literal_string) {
            return static_cast<std::size_t>(object_ref().via.str.size);
        }
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
        return static_cast<std::size_t>(object_ref().via.array.size);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    [[nodiscard]] object_type type() const noexcept
    {
        return static_cast<object_type>(object_ref().type);
    }

    [[nodiscard]] const char *data() const noexcept
    {
        if (type() == object_type::small_string) {
            return object_ref().via.sstr.data.data();
        }
        return object_ref().via.str.ptr;
    }
    // The is_* methods can be used to check for collections of types
    [[nodiscard]] bool is_container() const noexcept { return ddwaf::is_container(type()); }
    [[nodiscard]] bool is_scalar() const noexcept { return ddwaf::is_scalar(type()); }

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
        const auto &obj = object_ref();
        return obj.via.b8.val;
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_signed_v<T>
    {
        const auto &obj = object_ref();
        return static_cast<T>(obj.via.i64.val);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_integral_v<T> && std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
    {
        const auto &obj = object_ref();
        return static_cast<T>(obj.via.u64.val);
    }

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, double>
    {
        const auto &obj = object_ref();
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

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, array_view>;

    template <typename T>
    [[nodiscard]] T as() const noexcept
        requires std::is_same_v<T, map_view>;

    // Access the underlying value based on the required type or return a default
    // value otherwise.
    template <typename T> [[nodiscard]] T as_or_default(T default_value) const noexcept
    {
        const auto &obj = object_ref();
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
        const auto &obj = object_ref();
        return is_compatible_type<uint64_t>(type()) && obj.via.u64.val <= limits::max();
    }

    // Overload for other signed integer types
    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires(!std::is_same_v<T, int64_t>) && std::is_integral_v<T> && std::is_signed_v<T>
    {
        using limits = std::numeric_limits<T>;
        const auto &obj = object_ref();
        return is_compatible_type<int64_t>(type()) && obj.via.i64.val >= limits::min() &&
               obj.via.i64.val <= limits::max();
    }

    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires std::is_same_v<T, array_view>
    {
        return is_array();
    }

    template <typename T>
    [[nodiscard]] bool is() const noexcept
        requires std::is_same_v<T, map_view>
    {
        return is_map();
    }

    // Convert the underlying type to the requested type
    template <typename T> T convert() const;

    [[nodiscard]] owned_object clone() const;

private:
    readable_object() = default;
    [[nodiscard, gnu::always_inline]] const detail::object &object_ref() const
    {
        return static_cast<const Derived *>(this)->ref();
    }

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

class array_view {
public:
    array_view() = default;

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    array_view(const detail::object *o)
    {
        if (o == nullptr || o->type != object_type::array) {
            throw std::invalid_argument("array_view initialised with null or incompatible type");
        }
        data_ = o->via.array.ptr;
        size_ = o->via.array.size;
    }
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    array_view(const detail::object &o) : array_view(&o) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    array_view(object_view o) : array_view(o.ptr()) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    array_view(const owned_object &ow);
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    array_view(const borrowed_object &ow);

    array_view(owned_object &&ow) = delete;

    ~array_view() = default;
    array_view(const array_view &) = default;
    array_view(array_view &&) = default;
    array_view &operator=(const array_view &) = default;
    array_view &operator=(array_view &&) = default;

    [[nodiscard]] std::size_t size() const noexcept
    {
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
        return static_cast<std::size_t>(size_);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    // Access the value at index.
    [[nodiscard]] object_view at(std::size_t index) const noexcept
    {
        assert(index < size() && data_ != nullptr);
        return data_[index];
    }

    class iterator {
    public:
        ~iterator() = default;
        iterator(const iterator &) = default;
        iterator(iterator &&) = default;
        iterator &operator=(const iterator &) = default;
        iterator &operator=(iterator &&) = default;

        bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }
        object_view operator*() const { return current_; }
        iterator &operator++() noexcept
        {
            ++current_;
            return *this;
        }

    protected:
        iterator() = default;

        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        explicit iterator(const detail::object *start, const detail::object *end)
            : current_(start), end_(end)
        {}

        const detail::object *current_{nullptr};
        const detail::object *end_{nullptr};

        friend class array_view;
    };

    [[nodiscard]] iterator begin() const { return iterator{data_, data_ + size_}; }

    [[nodiscard]] iterator end() const { return iterator{data_ + size_, data_ + size_}; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object *data_{nullptr};
    uint16_t size_{0};
};

static_assert(sizeof(array_view) <= 16);
static_assert(sizeof(array_view::iterator) <= 16);

class map_view {
public:
    map_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_view(const detail::object *o)
    {
        if (o == nullptr || o->type != object_type::map) {
            throw std::invalid_argument("map_view initialised with null or incompatible type");
        }

        data_ = o->via.map.ptr;
        size_ = o->via.map.size;
    }
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_view(const detail::object &o) : map_view(&o) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_view(object_view o) : map_view(o.ptr()) {}
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_view(const owned_object &ow);
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_view(const borrowed_object &ow);

    map_view(owned_object &&ow) = delete;

    ~map_view() = default;
    map_view(const map_view &) = default;
    map_view(map_view &&) = default;
    map_view &operator=(const map_view &) = default;
    map_view &operator=(map_view &&) = default;

    [[nodiscard]] std::size_t size() const noexcept
    {
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
        return static_cast<std::size_t>(size_);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    // Access the value at index.
    [[nodiscard]] std::pair<object_view, object_view> at(std::size_t index) const noexcept
    {
        assert(index < size() && data_ != nullptr);
        const auto &kv = data_[index];
        return {kv.key, kv.val};
    }

    [[nodiscard]] object_view at_value(std::size_t index) const noexcept
    {
        assert(index < size() && data_ != nullptr);
        return data_[index].val;
    }

    [[nodiscard]] object_view at_key(std::size_t index) const noexcept
    {
        assert(index < size() && data_ != nullptr);
        return data_[index].key;
    }

    [[nodiscard]] object_view find(std::string_view expected_key) const noexcept
    {
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
        for (auto it = key_path.begin(); it != key_path.end(); ++it) {
            object_view child = root.find(*it);
            if ((it + 1) == key_path.end()) {
                return child;
            }

            if (!child.has_value() || !child.is_map()) {
                break;
            }

            root = child;
        }
        return {};
    }

    class iterator {
    public:
        ~iterator() = default;
        iterator(const iterator &) = default;
        iterator(iterator &&) = default;
        iterator &operator=(const iterator &) = default;
        iterator &operator=(iterator &&) = default;

        bool operator!=(const iterator &rhs) const noexcept { return current_ != rhs.current_; }

        std::pair<object_view, object_view> operator*() const
        {
            return {current_->key, current_->val};
        }

        iterator &operator++() noexcept
        {
            ++current_;
            return *this;
        }

    protected:
        iterator() = default;

        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        explicit iterator(const detail::object_kv *start, const detail::object_kv *end)
            : current_(start), end_(end)
        {}

        const detail::object_kv *current_{nullptr};
        const detail::object_kv *end_{nullptr};

        friend class map_view;
    };

    [[nodiscard]] iterator begin() const { return iterator{data_, data_ + size_}; }
    [[nodiscard]] iterator end() const { return iterator{data_ + size_, data_ + size_}; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object_kv *data_{nullptr};
    std::uint16_t size_{0};
};

static_assert(sizeof(map_view) <= 16);
static_assert(sizeof(map_view::iterator) <= 16);

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
    detail::object &object_ref() { return static_cast<Derived *>(this)->ref(); }

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

    [[nodiscard]] detail::object &ref() noexcept { return *obj_; }
    [[nodiscard]] const detail::object &ref() const noexcept { return *obj_; }
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

    [[nodiscard]] detail::object &ref() noexcept { return obj_; }
    [[nodiscard]] const detail::object &ref() const noexcept { return obj_; }
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

    static owned_object make_string_literal(const char *str, std::size_t len)
    {
        return owned_object{{.via{.str{.type = object_type::literal_string,
            .size = static_cast<uint32_t>(len),
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            .ptr = const_cast<char *>(str)}}}};
    }

    static owned_object make_string_nocopy(
        const char *str, std::size_t len, detail::object_free_fn free_fn = detail::object_free)
    {
        return owned_object{{.via{.str{.type = object_type::string,
                                .size = static_cast<uint32_t>(len),
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

        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        return owned_object{{.via{.str{.type = object_type::string,
                                .size = static_cast<uint32_t>(len),
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

inline array_view::array_view(const owned_object &ow) : array_view(ow.ptr()) {}
inline array_view::array_view(const borrowed_object &ow) : array_view(ow.ptr()) {}

inline map_view::map_view(const owned_object &ow) : map_view(ow.ptr()) {}
inline map_view::map_view(const borrowed_object &ow) : map_view(ow.ptr()) {}

template <typename Derived>
template <typename T>
[[nodiscard]] T readable_object<Derived>::as() const noexcept
    requires std::is_same_v<T, array_view>
{
    return array_view{object_ref()};
}

template <typename Derived>
template <typename T>
[[nodiscard]] T readable_object<Derived>::as() const noexcept
    requires std::is_same_v<T, map_view>
{
    return map_view{object_ref()};
}

// Convert the underlying type to the requested type, converters are defined
// in the object_converter header
template <typename Derived> template <typename T> T readable_object<Derived>::convert() const
{
    return object_converter<T>{object_ref()}();
}

template <typename Derived> [[nodiscard]] owned_object readable_object<Derived>::clone() const
{
    auto clone_helper = [](object_view source) -> owned_object {
        switch (source.type()) {
        case object_type::boolean:
            return owned_object::make_boolean(source.as<bool>());
        case object_type::string:
        case object_type::small_string:
            return owned_object::make_string(source.as<std::string_view>());
        case object_type::literal_string:
            return owned_object::make_string_literal(source.data(), source.size());
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

    const object_view input = object_ref();
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
        case object_type::literal_string:
        case object_type::small_string:
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
    auto &container = object_ref();

    assert(is_container(static_cast<object_type>(container.type)));

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
    auto &container = object_ref();

    assert(static_cast<object_type>(container.type) == object_type::array);

    // We preallocate 8 entries
    if (container.via.array.size == 0) {
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.array.ptr = detail::alloc_helper<detail::object>(8U);
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.array.capacity = 8;
    } else if (container.via.array.capacity == container.via.array.size) {
        auto [new_array, new_capacity] =
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            detail::realloc_helper(container.via.array.ptr, container.via.array.capacity);
        container.via.array.ptr = new_array;
        container.via.array.capacity = new_capacity;
    }

    borrowed_object slot{&container.via.array.ptr[container.via.array.size++]};
    slot = std::move(value);
    return slot;
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
    auto &container = object_ref();
    assert(static_cast<object_type>(container.type) == object_type::map);

    // We preallocate 8 entries
    if (container.via.map.size == 0) {
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.map.ptr = detail::alloc_helper<detail::object_kv>(8U);
        // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
        container.via.map.capacity = 8;
    } else if (container.via.map.capacity == container.via.map.size) {
        auto [new_map, new_capacity] =
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            detail::realloc_helper(container.via.map.ptr, container.via.map.capacity);
        container.via.map.ptr = new_map;
        container.via.map.capacity = new_capacity;
    }

    borrowed_object key_slot{container.via.map.ptr[container.via.map.size].key};
    borrowed_object val_slot{container.via.map.ptr[container.via.map.size].val};
    ++container.via.map.size;

    key_slot = std::move(key);
    val_slot = std::move(value);

    return val_slot;
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
