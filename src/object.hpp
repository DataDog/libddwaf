// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "dynamic_string.hpp"
#include "memory_resource.hpp"
#include "object_type.hpp"
#include "pointer.hpp"
#include "traits.hpp"
#include "utils.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <initializer_list>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <variant>

namespace ddwaf {

class object_view;
class map_view;
class array_view;

class owned_object;
class borrowed_object;

class object_cache_key;

template <typename T> struct object_converter;

namespace detail {

union object;
struct object_kv;
struct object_large_array_storage;
struct object_large_map_storage;

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

struct object_large_array {
    object_type type;
    uint8_t reserved[7];
    union {
        uint64_t _padding;
        object *ptr;
    };
};

struct object_large_map {
    object_type type;
    uint8_t reserved[7];
    union {
        uint64_t _padding;
        object_kv *ptr;
    };
};

union [[gnu::may_alias]] object {
    object_type type;
    union {
        object_scalar<bool> b8;
        object_scalar<int64_t> i64;
        object_scalar<uint64_t> u64;
        object_scalar<double> f64;
        object_string str;
        object_small_string sstr;
        object_array array;
        object_map map;
        object_large_array large_array;
        object_large_map large_map;
    } via;
};

struct object_kv {
    object key;
    object val;
};

struct alignas(object) object_large_array_storage {
    std::size_t size;
    std::size_t capacity;
    object ptr[];
};

struct alignas(object_kv) object_large_map_storage {
    std::size_t size;
    std::size_t capacity;
    object_kv ptr[];
};

static_assert(sizeof(object) == 16);
static_assert(sizeof(object_kv) == 32);
static_assert(sizeof(object_large_array) == sizeof(object));
static_assert(sizeof(object_large_map) == sizeof(object));

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
static_assert(offsetof(object, type) == offsetof(object_large_array, type));
static_assert(offsetof(object, type) == offsetof(object_large_map, type));

static_assert(offsetof(object_map, size) == offsetof(object_array, size));
static_assert(offsetof(object_map, capacity) == offsetof(object_array, capacity));
static_assert(offsetof(object_map, ptr) == offsetof(object_array, ptr));

static_assert(offsetof(object_array, ptr) == offsetof(object_large_array, ptr));
static_assert(offsetof(object_map, ptr) == offsetof(object_large_map, ptr));
static_assert(offsetof(object_large_array_storage, ptr) == sizeof(object_large_array_storage));
static_assert(offsetof(object_large_map_storage, ptr) == sizeof(object_large_map_storage));
static_assert(alignof(object_large_array_storage) >= alignof(object));
static_assert(alignof(object_large_map_storage) >= alignof(object_kv));

template <typename T> constexpr std::size_t maxof_v = std::numeric_limits<T>::max();

#define DDWAF_CONTAINER_OF(pointer, type, member)                                                  \
    reinterpret_cast<type *>(reinterpret_cast<std::byte *>(pointer) - offsetof(type, member))

/*
 * Converts a signed index to an absolute container offset. Nonnegative indices
 * count from the front, negative indices count from the back (-1 is last), and
 * indices outside the container return std::nullopt.
 */
inline std::optional<std::size_t> normalize_index(std::size_t size, int64_t index) noexcept
{
    if (index >= 0) {
        const auto unsigned_index = static_cast<uint64_t>(index);
        if (unsigned_index < size) {
            return static_cast<std::size_t>(unsigned_index);
        }
        return std::nullopt;
    }

    // Avoid negating INT64_MIN directly, which would overflow.
    const auto distance = static_cast<uint64_t>(-(index + 1)) + uint64_t{1};
    if (distance > size) {
        return std::nullopt;
    }
    return size - static_cast<std::size_t>(distance);
}

template <typename Storage, typename Element>
inline Storage *large_storage_from_data(Element *data) noexcept
{
    if (data == nullptr) {
        return nullptr;
    }
    return DDWAF_CONTAINER_OF(data, Storage, ptr);
}

#undef DDWAF_CONTAINER_OF

inline object_large_array_storage *large_array_storage(object &obj) noexcept
{
    return large_storage_from_data<object_large_array_storage>(obj.via.large_array.ptr);
}

inline const object_large_array_storage *large_array_storage(const object &obj) noexcept
{
    return large_storage_from_data<object_large_array_storage>(obj.via.large_array.ptr);
}

inline object_large_map_storage *large_map_storage(object &obj) noexcept
{
    return large_storage_from_data<object_large_map_storage>(obj.via.large_map.ptr);
}

inline const object_large_map_storage *large_map_storage(const object &obj) noexcept
{
    return large_storage_from_data<object_large_map_storage>(obj.via.large_map.ptr);
}

inline std::size_t container_size(const object &obj)
{
    if (obj.type == object_type::large_array) [[unlikely]] {
        const auto *storage = large_array_storage(obj);
        return storage == nullptr ? 0 : storage->size;
    }
    if (obj.type == object_type::large_map) [[unlikely]] {
        const auto *storage = large_map_storage(obj);
        return storage == nullptr ? 0 : storage->size;
    }
    return obj.via.array.size;
}

/*
 * Compact and large containers store the same element pointer type at this
 * offset. Copying its representation avoids reading an inactive union member.
 */
template <typename Element> inline Element *container_data(object &obj) noexcept
{
    Element *data;
    memcpy(&data, reinterpret_cast<const std::byte *>(&obj) + offsetof(object_array, ptr),
        sizeof(data));
    return data;
}

template <typename Element> inline const Element *container_data(const object &obj) noexcept
{
    Element *data;
    memcpy(&data, reinterpret_cast<const std::byte *>(&obj) + offsetof(object_array, ptr),
        sizeof(data));
    return data;
}

inline object *array_data(object &obj) noexcept { return container_data<object>(obj); }

inline const object *array_data(const object &obj) noexcept { return container_data<object>(obj); }

inline object_kv *map_data(object &obj) noexcept { return container_data<object_kv>(obj); }

inline const object_kv *map_data(const object &obj) noexcept
{
    return container_data<object_kv>(obj);
}

inline bool requires_allocator(object_type type)
{
    // Container or non-const, non-small, string
    return is_container(type) || type == object_type::string;
}

template <typename T, typename SizeType>
inline T *alloc_helper(SizeType size, memory::memory_resource &alloc)
    requires(std::is_unsigned_v<SizeType> && sizeof(SizeType) <= sizeof(std::size_t))
{
    static_assert(maxof_v<SizeType> <= maxof_v<std::size_t> / sizeof(T));

    return static_cast<T *>(alloc.allocate(sizeof(T) * size, alignof(T)));
}

template <typename T, typename SizeType>
inline void dealloc_helper(T *ptr, SizeType size, memory::memory_resource &alloc)
    requires(std::is_unsigned_v<SizeType> && sizeof(SizeType) <= sizeof(std::size_t))
{
    alloc.deallocate(ptr, sizeof(T) * size, alignof(T));
}

template <typename T, typename SizeType>
inline std::pair<T *, SizeType> realloc_helper(
    T *data, SizeType size, memory::memory_resource &alloc)
    requires(std::is_unsigned_v<SizeType> && sizeof(SizeType) <= sizeof(std::size_t))
{
    static_assert(maxof_v<SizeType> <= maxof_v<std::size_t> / sizeof(T));

    constexpr std::size_t max_elements = maxof_v<SizeType>;

    SizeType new_size;
    if (size > max_elements / 2) [[unlikely]] {
        new_size = max_elements;
    } else {
        new_size = size * 2;
    }

    auto *new_data = static_cast<T *>(alloc.allocate(sizeof(T) * new_size, alignof(T)));
    memcpy(new_data, data, sizeof(T) * size);

    dealloc_helper(data, size, alloc);

    return {new_data, new_size};
}

template <typename Storage, typename Element>
constexpr std::size_t max_large_storage_capacity =
    (maxof_v<std::size_t> - sizeof(Storage)) / sizeof(Element);

template <typename Storage, typename Element>
inline std::size_t large_storage_bytes(std::size_t capacity)
{
    if (capacity > max_large_storage_capacity<Storage, Element>) [[unlikely]] {
        throw std::length_error("container capacity exceeds allocation limit");
    }
    return sizeof(Storage) + capacity * sizeof(Element);
}

template <typename Storage, typename Element>
inline Storage *alloc_large_storage(std::size_t capacity, memory::memory_resource &alloc)
{
    if (capacity == 0) {
        return nullptr;
    }

    const auto bytes = large_storage_bytes<Storage, Element>(capacity);
    auto *storage = static_cast<Storage *>(alloc.allocate(bytes, alignof(Storage)));
    if (storage == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }
    storage->size = 0;
    storage->capacity = capacity;
    return storage;
}

template <typename Storage, typename Element>
inline void dealloc_large_storage(Storage *storage, memory::memory_resource &alloc)
{
    const auto bytes = large_storage_bytes<Storage, Element>(storage->capacity);
    alloc.deallocate(storage, bytes, alignof(Storage));
}

inline std::size_t next_large_capacity(std::size_t capacity, std::size_t maximum)
{
    if (capacity >= maximum) [[unlikely]] {
        throw std::length_error("container has reached its maximum capacity");
    }
    if (capacity == 0) {
        return std::min<std::size_t>(8, maximum);
    }
    return capacity > maximum / 2 ? maximum : capacity * 2;
}

inline void grow_large_array(object &obj, memory::memory_resource &alloc)
{
    auto *old_storage = large_array_storage(obj);
    const auto old_capacity = old_storage == nullptr ? 0 : old_storage->capacity;
    const auto old_size = old_storage == nullptr ? 0 : old_storage->size;
    static constexpr auto maximum = max_large_storage_capacity<object_large_array_storage, object>;
    const auto new_capacity = next_large_capacity(old_capacity, maximum);
    auto *new_storage =
        alloc_large_storage<object_large_array_storage, object>(new_capacity, alloc);
    new_storage->size = old_size;
    if (old_storage != nullptr) {
        memcpy(new_storage->ptr, old_storage->ptr, old_size * sizeof(object));
        dealloc_large_storage<object_large_array_storage, object>(old_storage, alloc);
    }
    obj.via.large_array.ptr = new_storage->ptr;
}

inline void grow_large_map(object &obj, memory::memory_resource &alloc)
{
    auto *old_storage = large_map_storage(obj);
    const auto old_capacity = old_storage == nullptr ? 0 : old_storage->capacity;
    const auto old_size = old_storage == nullptr ? 0 : old_storage->size;
    static constexpr auto maximum = max_large_storage_capacity<object_large_map_storage, object_kv>;
    const auto new_capacity = next_large_capacity(old_capacity, maximum);
    auto *new_storage =
        alloc_large_storage<object_large_map_storage, object_kv>(new_capacity, alloc);
    new_storage->size = old_size;
    if (old_storage != nullptr) {
        memcpy(new_storage->ptr, old_storage->ptr, old_size * sizeof(object_kv));
        dealloc_large_storage<object_large_map_storage, object_kv>(old_storage, alloc);
    }
    obj.via.large_map.ptr = new_storage->ptr;
}

inline void promote_array(object &obj, memory::memory_resource &alloc)
{
    constexpr std::size_t promoted_capacity = maxof_v<uint16_t> * std::size_t{2};
    auto *storage =
        alloc_large_storage<object_large_array_storage, object>(promoted_capacity, alloc);
    storage->size = obj.via.array.size;
    memcpy(storage->ptr, obj.via.array.ptr, storage->size * sizeof(object));
    dealloc_helper(obj.via.array.ptr, obj.via.array.capacity, alloc);
    obj = {
        .via{.large_array{.type = object_type::large_array, .reserved = {}, .ptr = storage->ptr}}};
}

inline void promote_map(object &obj, memory::memory_resource &alloc)
{
    constexpr std::size_t promoted_capacity = maxof_v<uint16_t> * std::size_t{2};
    auto *storage =
        alloc_large_storage<object_large_map_storage, object_kv>(promoted_capacity, alloc);
    storage->size = obj.via.map.size;
    memcpy(storage->ptr, obj.via.map.ptr, storage->size * sizeof(object_kv));
    dealloc_helper(obj.via.map.ptr, obj.via.map.capacity, alloc);
    obj = {.via{.large_map{.type = object_type::large_map, .reserved = {}, .ptr = storage->ptr}}};
}

template <typename SizeType>
inline char *copy_string(const char *str, SizeType length, memory::memory_resource &alloc)
{
    auto *copy = alloc_helper<char, uint32_t>(length, alloc);
    memcpy(copy, str, length);
    return copy;
}

// NOLINTNEXTLINE(misc-no-recursion)
inline void object_destroy(object &obj, nonnull_ptr<memory::memory_resource> alloc)
{
    if (alloc->is_equal(*memory::get_default_null_resource())) {
        return;
    }

    if (ddwaf::is_array(obj.type)) {
        const auto size = container_size(obj);
        auto *data = array_data(obj);
        for (std::size_t i = 0; i < size; ++i) { object_destroy(data[i], alloc); }
        if (obj.type == object_type::large_array && obj.via.large_array.ptr != nullptr)
            [[unlikely]] {
            dealloc_large_storage<object_large_array_storage, object>(
                large_array_storage(obj), *alloc);
        } else if (obj.type == object_type::array && obj.via.array.ptr != nullptr) {
            dealloc_helper(obj.via.array.ptr, obj.via.array.capacity, *alloc);
        }
    } else if (ddwaf::is_map(obj.type)) {
        const auto size = container_size(obj);
        auto *data = map_data(obj);
        for (std::size_t i = 0; i < size; ++i) {
            object_destroy(data[i].key, alloc);
            object_destroy(data[i].val, alloc);
        }
        if (obj.type == object_type::large_map && obj.via.large_map.ptr != nullptr) [[unlikely]] {
            dealloc_large_storage<object_large_map_storage, object_kv>(
                large_map_storage(obj), *alloc);
        } else if (obj.type == object_type::map && obj.via.map.ptr != nullptr) {
            dealloc_helper(obj.via.map.ptr, obj.via.map.capacity, *alloc);
        }
    } else if (obj.type == object_type::string) {
        if (obj.via.str.ptr != nullptr) {
            dealloc_helper(obj.via.str.ptr, obj.via.str.size, *alloc);
        }
    }
}

inline bool alloc_equal(
    nonnull_ptr<memory::memory_resource> left, nonnull_ptr<memory::memory_resource> right)
{
    return left == right || left->is_equal(*right);
}

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
            return object_ref().via.sstr.size;
        }

        if (t == object_type::string || t == object_type::literal_string) {
            return object_ref().via.str.size;
        }
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
        return detail::container_size(object_ref());
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

    [[nodiscard]] bool is_map() const noexcept { return ddwaf::is_map(type()); }
    [[nodiscard]] bool is_array() const noexcept { return ddwaf::is_array(type()); }
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

    [[nodiscard]] owned_object clone(nonnull_ptr<memory::memory_resource> alloc) const;

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
        } else if constexpr (is_type_in_set_v<std::decay_t<T>, std::string_view, std::string>) {
            return has_value() && is_string() && as<std::string_view>() == other;
        } else {
            static_assert(!std::is_same_v<T, T>, "unsupported type for object_view::operator==");
        }
    }
    template <typename T> bool operator!=(const T &other) const
    {
        if constexpr (std::is_same_v<std::decay_t<T>, object_view>) {
            return ptr() != other.ptr();
        } else if constexpr (is_type_in_set_v<std::decay_t<T>, std::string_view, std::string>) {
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
        if (is_map()) {
            const auto *data = detail::map_data(*obj_);
            assert(data != nullptr);
            const auto &slot = data[index];
            return {slot.key, slot.val};
        }
        const auto *data = detail::array_data(*obj_);
        assert(data != nullptr);
        return {{}, data[index]};
    }

    // Access the key at index. If the container is an array, the key will be an empty string.
    [[nodiscard]] object_view at_key(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size());
        if (is_map()) {
            const auto *data = detail::map_data(*obj_);
            assert(data != nullptr);
            return data[index].key;
        }
        assert(detail::array_data(*obj_) != nullptr);
        return {};
    }

    // Access the value at index.
    [[nodiscard]] object_view at_value(std::size_t index) const noexcept
    {
        assert(obj_ != nullptr && index < size());
        if (is_map()) {
            const auto *data = detail::map_data(*obj_);
            assert(data != nullptr);
            return data[index].val;
        }
        const auto *data = detail::array_data(*obj_);
        assert(data != nullptr);
        return data[index];
    }

    [[nodiscard]] object_view find(std::string_view expected_key) const noexcept
    {
        assert(obj_ != nullptr && is_map());

        for (std::size_t i = 0; i < size(); ++i) {
            auto [key, value] = at(i);

            if (expected_key == key.as<std::string_view>()) {
                return value;
            }
        }
        return {};
    }

    template <typename T = std::unordered_set<object_cache_key>>
    object_view find_key_path(
        std::span<const std::variant<std::string, int64_t>> key_path, const T &exclusion = {})
    {
        auto root = *this;

        if (!root.has_value() || exclusion.contains(root)) {
            return {};
        }

        for (auto it = key_path.begin(); it != key_path.end(); ++it) {
            root = std::visit(
                [root](auto &&expected_key) -> object_view {
                    using U = std::decay_t<decltype(expected_key)>;
                    if constexpr (std::is_same_v<U, std::string>) {
                        if (!root.is_map()) {
                            return {};
                        }

                        for (std::size_t i = 0; i < root.size(); ++i) {
                            const auto &[key, child] = root.at(i);

                            auto child_key = key.as<std::string_view>();
                            if (expected_key == child_key) {
                                return child;
                            }
                        }
                    } else if constexpr (std::is_same_v<U, int64_t>) {
                        if (!root.is_array()) {
                            return {};
                        }

                        if (const auto index = detail::normalize_index(root.size(), expected_key)) {
                            return root.at_value(*index);
                        }
                    }
                    return {};
                },
                *it);

            if (!root.has_value() || exclusion.contains(root)) {
                return {};
            }
        }
        return root;
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
        if (o == nullptr || !ddwaf::is_array(o->type)) {
            throw std::invalid_argument("array_view initialised with null or incompatible type");
        }
        data_ = detail::array_data(*o);
        size_ = detail::container_size(*o);
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
        explicit iterator(const detail::object *start) : current_(start) {}

        const detail::object *current_{nullptr};

        friend class array_view;
    };

    [[nodiscard]] iterator begin() const { return iterator{data_}; }

    [[nodiscard]] iterator end() const { return iterator{data_ + size_}; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object *data_{nullptr};
    std::size_t size_{0};
};

static_assert(sizeof(array_view) <= 16);
static_assert(sizeof(array_view::iterator) <= 16);

class map_view {
public:
    map_view() = default;
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    map_view(const detail::object *o)
    {
        if (o == nullptr || !ddwaf::is_map(o->type)) {
            throw std::invalid_argument("map_view initialised with null or incompatible type");
        }

        data_ = detail::map_data(*o);
        size_ = detail::container_size(*o);
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
        explicit iterator(const detail::object_kv *start) : current_(start) {}

        const detail::object_kv *current_{nullptr};

        friend class map_view;
    };

    [[nodiscard]] iterator begin() const { return iterator{data_}; }
    [[nodiscard]] iterator end() const { return iterator{data_ + size_}; }

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const detail::object_kv *data_{nullptr};
    std::size_t size_{0};
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
    nonnull_ptr<memory::memory_resource> alloc() { return static_cast<Derived *>(this)->alloc(); }

    friend Derived;
};

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class borrowed_object final : public readable_object<borrowed_object>,
                              public writable_object<borrowed_object> {
public:
    explicit borrowed_object(owned_object &obj);
    borrowed_object &operator=(owned_object &&obj);

    // UNSAFE: Caller must ensure the object's memory is compatible with the allocator
    borrowed_object(detail::object *obj, nonnull_ptr<memory::memory_resource> alloc)
        : obj_(obj), alloc_(alloc)
    {
        if (obj == nullptr) {
            throw std::invalid_argument("invalid borrowed object (null)");
        }
    }

    // UNSAFE: Caller must ensure the object's memory is compatible with the allocator
    borrowed_object(detail::object &obj, nonnull_ptr<memory::memory_resource> alloc)
        : obj_(&obj), alloc_(alloc)
    {}

    [[nodiscard]] detail::object &ref() noexcept { return *obj_; }
    [[nodiscard]] const detail::object &ref() const noexcept { return *obj_; }
    [[nodiscard]] detail::object *ptr() { return obj_; }
    [[nodiscard]] const detail::object *ptr() const noexcept { return obj_; }
    [[nodiscard]] nonnull_ptr<memory::memory_resource> alloc() const noexcept { return alloc_; }

protected:
    detail::object *obj_;
    nonnull_ptr<memory::memory_resource> alloc_;

    friend class owned_object;
    friend class object_view;
};

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class owned_object final : public readable_object<owned_object>,
                           public writable_object<owned_object> {
public:
    owned_object()
        : obj_({.type = object_type::invalid}), alloc_(memory::get_default_null_resource())
    {}

    // UNSAFE: Caller must ensure the object's memory is compatible with the
    // allocator. In particular:
    // 1) if it needs to be deallocated, alloc must be able to do so
    // 2) if it is a map or array that requires resizing, alloc must be able to
    //    free the current chunk and allocate a new one
    // 3) if it contains sub-objects, the requirements apply transitively
    owned_object(detail::object obj, nonnull_ptr<memory::memory_resource> alloc)
        : obj_(obj), alloc_(alloc)
    {}

    ~owned_object() { detail::object_destroy(obj_, alloc_); }

    owned_object(const owned_object &) = delete;
    owned_object &operator=(const owned_object &) = delete;

    owned_object(owned_object &&other) noexcept : obj_(other.obj_), alloc_(other.alloc_)
    {
        other.obj_ = detail::object{.type = object_type::invalid};
    }

    owned_object &operator=(owned_object &&other) noexcept
    {
        detail::object_destroy(obj_, alloc_);

        obj_ = other.obj_;
        alloc_ = other.alloc_;
        other.obj_ = detail::object{.type = object_type::invalid};
        return *this;
    }

    [[nodiscard]] detail::object &ref() noexcept { return obj_; }
    [[nodiscard]] const detail::object &ref() const noexcept { return obj_; }
    [[nodiscard]] detail::object *ptr() { return &obj_; }
    [[nodiscard]] const detail::object *ptr() const noexcept { return &obj_; }
    [[nodiscard]] nonnull_ptr<memory::memory_resource> alloc() const noexcept { return alloc_; }

    // the variants that don't take a memory resource can't be written to
    // (have their value replaced)

    static owned_object make_null()
    {
        return owned_object({.type = object_type::null}, memory::get_default_null_resource());
    }

    static owned_object make_boolean(bool value)
    {
        return owned_object({.via{.b8{.type = object_type::boolean, .val = value}}},
            memory::get_default_null_resource());
    }

    static owned_object make_signed(int64_t value)
    {
        return owned_object({.via{.i64{.type = object_type::int64, .val = value}}},
            memory::get_default_null_resource());
    }

    static owned_object make_unsigned(uint64_t value)
    {
        return owned_object({.via{.u64{.type = object_type::uint64, .val = value}}},
            memory::get_default_null_resource());
    }

    static owned_object make_float(double value)
    {
        return owned_object({.via{.f64{.type = object_type::float64, .val = value}}},
            memory::get_default_null_resource());
    }

    // Unsafe insofar as the string is not copied - the caller must ensure
    // the string memory remains valid for the lifetime of the object
    static owned_object make_string_literal(const char *str, std::uint32_t len)
    {
        return owned_object({.via{.str{.type = object_type::literal_string,
                                .size = static_cast<uint32_t>(len),
                                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                .ptr = const_cast<char *>(str)}}},
            memory::get_default_null_resource());
    }

    // UNSAFE: Does not copy the string - caller must ensure the string memory
    // can be deallocated by alloc
    static owned_object make_string_nocopy(
        const char *str, std::uint32_t len, nonnull_ptr<memory::memory_resource> alloc)
    {
        return owned_object({.via{.str{.type = object_type::string,
                                .size = len,
                                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                .ptr = const_cast<char *>(str)}}},
            alloc);
    }

    // UNSAFE: Does not copy the string - caller must ensure the string memory
    // can be deallocated by alloc
    static owned_object make_string_nocopy(
        std::same_as<std::string_view> auto str, nonnull_ptr<memory::memory_resource> alloc)
    {
        return make_string_nocopy(str.data(), str.size(), alloc);
    }

    static owned_object make_string(
        const char *str, std::uint32_t len, nonnull_ptr<memory::memory_resource> alloc)
    {
        if (len <= detail::small_string_size) {
            owned_object obj({.via{.sstr{.type = object_type::small_string,
                                 .size = static_cast<uint8_t>(len),
                                 .data = {}}}},
                alloc);

            if (str != nullptr && len > 0) {
                memcpy(obj.obj_.via.sstr.data.data(), str, len);
            }

            return obj;
        }

        return owned_object({.via{.str{.type = object_type::string,
                                .size = len,
                                .ptr = detail::copy_string(str, len, *alloc)}}},
            alloc);
    }

    static owned_object make_string(
        std::string_view str, nonnull_ptr<memory::memory_resource> alloc)
    {
        if (str.empty()) {
            return make_string("", 0, alloc);
        }
        return make_string(str.data(), str.size(), alloc);
    }

    static owned_object make_array(std::size_t capacity, nonnull_ptr<memory::memory_resource> alloc)
    {
        if (capacity > detail::maxof_v<uint16_t>) [[unlikely]] {
            return make_large_array(capacity, alloc);
        }

        const auto compact_capacity = static_cast<uint16_t>(capacity);
        if (capacity == 0) {
            return owned_object{
                {.via{
                    .array{.type = object_type::array, .size = 0, .capacity = 0, .ptr = nullptr}}},
                alloc};
        }

        return owned_object{
            {.via{.array{.type = object_type::array,
                .size = 0,
                .capacity = compact_capacity,
                .ptr = detail::alloc_helper<detail::object, uint16_t>(compact_capacity, *alloc)}}},
            alloc};
    }

    static owned_object make_array(nonnull_ptr<memory::memory_resource> alloc)
    {
        return make_array(0, alloc);
    }

    static owned_object make_large_array(
        std::size_t capacity, nonnull_ptr<memory::memory_resource> alloc)
    {
        auto *storage =
            detail::alloc_large_storage<detail::object_large_array_storage, detail::object>(
                capacity, *alloc);
        return owned_object{{.via{.large_array{.type = object_type::large_array,
                                .reserved = {},
                                .ptr = storage == nullptr ? nullptr : storage->ptr}}},
            alloc};
    }

    static owned_object make_map(std::size_t capacity, nonnull_ptr<memory::memory_resource> alloc)
    {
        if (capacity > detail::maxof_v<uint16_t>) [[unlikely]] {
            return make_large_map(capacity, alloc);
        }

        const auto compact_capacity = static_cast<uint16_t>(capacity);
        if (capacity == 0) {
            return owned_object{
                {.via{.map{.type = object_type::map, .size = 0, .capacity = 0, .ptr = nullptr}}},
                alloc};
        }

        return owned_object{{.via{.map{.type = object_type::map,
                                .size = 0,
                                .capacity = compact_capacity,
                                .ptr = detail::alloc_helper<detail::object_kv, uint16_t>(
                                    compact_capacity, *alloc)}}},
            alloc};
    }

    static owned_object make_map(nonnull_ptr<memory::memory_resource> alloc)
    {
        return make_map(0, alloc);
    }

    static owned_object make_large_map(
        std::size_t capacity, nonnull_ptr<memory::memory_resource> alloc)
    {
        auto *storage =
            detail::alloc_large_storage<detail::object_large_map_storage, detail::object_kv>(
                capacity, *alloc);
        return owned_object{{.via{.large_map{.type = object_type::large_map,
                                .reserved = {},
                                .ptr = storage == nullptr ? nullptr : storage->ptr}}},
            alloc};
    }

    detail::object move()
    {
        detail::object copy = obj_;
        obj_ = detail::object{.type = object_type::invalid};
        return copy;
    }

protected:
    detail::object obj_;
    nonnull_ptr<memory::memory_resource> alloc_;

    friend class borrowed_object;
    friend class object_view;
};

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
template <typename Derived>
template <typename T>
[[nodiscard]] [[nodiscard]] T readable_object<Derived>::convert() const
{
    return object_converter<T>{object_ref()}();
}

template <typename Derived>
[[nodiscard]] owned_object readable_object<Derived>::clone(
    nonnull_ptr<memory::memory_resource> alloc) const
{
    auto clone_helper = [](object_view source,
                            nonnull_ptr<memory::memory_resource> alloc) -> owned_object {
        switch (source.type()) {
        case object_type::boolean:
            return owned_object::make_boolean(source.as<bool>());
        case object_type::string:
        case object_type::small_string:
            return owned_object::make_string(source.as<std::string_view>(), alloc);
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
        case object_type::large_map:
            return owned_object::make_map(source.size(), alloc);
        case object_type::array:
        case object_type::large_array:
            return owned_object::make_array(source.size(), alloc);
        case object_type::invalid:
        default:
            break;
        }
        return owned_object{};
    };

    std::deque<std::pair<object_view, borrowed_object>> queue;

    const object_view input = object_ref();
    auto copy = clone_helper(input, alloc);
    if (copy.is_container()) {
        queue.emplace_front(input, copy);
    }

    while (!queue.empty()) {
        auto &[source, destination] = queue.front();
        for (uint64_t i = 0; i < source.size(); ++i) {
            const auto &[key, value] = source.at(i);
            if (source.is_map()) {
                destination.emplace(key.as<std::string_view>(), clone_helper(value, alloc));
            } else if (source.is_array()) {
                destination.emplace_back(clone_helper(value, alloc));
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
            return ddwaf::to_string(view.as<bool>());
        case object_type::uint64:
            return ddwaf::to_string(view.as<uint64_t>());
        case object_type::int64:
            return ddwaf::to_string(view.as<int64_t>());
        case object_type::float64:
            return ddwaf::to_string(view.as<double>());
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

    if (ddwaf::is_map(container.type)) {
        assert(idx < detail::container_size(container));
        return borrowed_object{&detail::map_data(container)[idx].val, alloc()};
    }

    assert(idx < detail::container_size(container));
    return borrowed_object{&detail::array_data(container)[idx], alloc()};
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object writable_object<Derived>::emplace_back(owned_object &&value)
{
    auto &container = object_ref();

    assert(ddwaf::is_array(container.type));

    if (detail::requires_allocator(value.type()) && !detail::alloc_equal(alloc(), value.alloc())) {
        throw std::runtime_error("emplace: incompatible allocators");
    }

    if (container.type == object_type::large_array) [[unlikely]] {
        auto *storage = detail::large_array_storage(container);
        if (storage == nullptr || storage->size == storage->capacity) {
            detail::grow_large_array(container, alloc());
            storage = detail::large_array_storage(container);
        }

        borrowed_object slot{&storage->ptr[storage->size++], alloc()};
        *slot.ptr() = value.move();
        return slot;
    }

    // We preallocate 8 entries
    if (container.via.array.capacity == 0) {
        container.via.array.ptr = detail::alloc_helper<detail::object, uint16_t>(8U, alloc());
        container.via.array.capacity = 8;
    } else if (container.via.array.capacity == container.via.array.size) {
        if (container.via.array.capacity == detail::maxof_v<uint16_t>) [[unlikely]] {
            detail::promote_array(container, alloc());
            auto *storage = detail::large_array_storage(container);
            borrowed_object slot{&storage->ptr[storage->size++], alloc()};
            *slot.ptr() = value.move();
            return slot;
        }

        auto [new_array, new_capacity] = detail::realloc_helper<detail::object, uint16_t>(
            container.via.array.ptr, container.via.array.capacity, alloc());
        container.via.array.ptr = new_array;
        container.via.array.capacity = new_capacity;
    }

    borrowed_object slot{&container.via.array.ptr[container.via.array.size++], alloc()};
    // don't do slot = std::move(value) as that would attempt to destroy slot
    // (but slot is uninitialized memory)
    *slot.ptr() = value.move();
    return slot;
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object writable_object<Derived>::emplace(std::string_view key, owned_object &&value)
{
    return emplace(owned_object::make_string(key, alloc()), std::move(value));
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved,bugprone-easily-swappable-parameters)
borrowed_object writable_object<Derived>::emplace(owned_object &&key, owned_object &&value)
{
    auto &container = object_ref();

    assert(ddwaf::is_map(container.type));

    if ((detail::requires_allocator(key.type()) && !detail::alloc_equal(alloc(), key.alloc())) ||
        (detail::requires_allocator(value.type()) &&
            !detail::alloc_equal(alloc(), value.alloc()))) {
        throw std::runtime_error("emplace: incompatible allocators");
    }

    if (container.type == object_type::large_map) {
        auto *storage = detail::large_map_storage(container);
        if (storage == nullptr || storage->size == storage->capacity) {
            detail::grow_large_map(container, alloc());
            storage = detail::large_map_storage(container);
        }

        borrowed_object key_slot{storage->ptr[storage->size].key, alloc()};
        borrowed_object val_slot{storage->ptr[storage->size].val, alloc()};
        ++storage->size;
        *key_slot.ptr() = key.move();
        *val_slot.ptr() = value.move();
        return val_slot;
    }

    // We preallocate 8 entries
    if (container.via.map.capacity == 0) {
        container.via.map.ptr = detail::alloc_helper<detail::object_kv, uint16_t>(8U, alloc());
        container.via.map.capacity = 8;
    } else if (container.via.map.capacity == container.via.map.size) {
        if (container.via.map.capacity == detail::maxof_v<uint16_t>) {
            detail::promote_map(container, alloc());
            auto *storage = detail::large_map_storage(container);
            borrowed_object key_slot{storage->ptr[storage->size].key, alloc()};
            borrowed_object val_slot{storage->ptr[storage->size].val, alloc()};
            ++storage->size;
            *key_slot.ptr() = key.move();
            *val_slot.ptr() = value.move();
            return val_slot;
        }

        auto [new_map, new_capacity] = detail::realloc_helper<detail::object_kv, uint16_t>(
            container.via.map.ptr, container.via.map.capacity, alloc());
        container.via.map.ptr = new_map;
        container.via.map.capacity = new_capacity;
    }

    borrowed_object key_slot{container.via.map.ptr[container.via.map.size].key, alloc()};
    borrowed_object val_slot{container.via.map.ptr[container.via.map.size].val, alloc()};
    ++container.via.map.size;

    // key_slot / val_slot are uninitialized memory, so don't do
    // key_slot = std::move(key) or val_slot = std::move(value)
    *key_slot.ptr() = key.move();
    *val_slot.ptr() = value.move();

    return val_slot;
}

template <typename Derived>
template <typename T>
borrowed_object writable_object<Derived>::emplace_back(T &&value)
{
    if constexpr (std::same_as<std::remove_cvref_t<T>, bool>) {
        return emplace_back(owned_object::make_boolean(std::forward<T>(value)));
    } else if constexpr (std::is_integral_v<std::remove_cvref_t<T>> &&
                         std::is_signed_v<std::remove_cvref_t<T>>) {
        return emplace_back(owned_object::make_signed(std::forward<T>(value)));
    } else if constexpr (std::is_integral_v<std::remove_cvref_t<T>> &&
                         std::is_unsigned_v<std::remove_cvref_t<T>>) {
        return emplace_back(owned_object::make_unsigned(std::forward<T>(value)));
    } else if constexpr (std::is_floating_point_v<std::remove_cvref_t<T>>) {
        return emplace_back(owned_object::make_float(std::forward<T>(value)));
    } else if constexpr (std::convertible_to<T, std::string_view>) {
        return emplace_back(
            owned_object::make_string(std::string_view(std::forward<T>(value)), alloc()));
    } else {
        return emplace_back(std::forward<T>(value));
    }
}

template <typename Derived>
template <typename T>
borrowed_object writable_object<Derived>::emplace(std::string_view key, T &&value)
{
    if constexpr (std::same_as<std::remove_cvref_t<T>, bool>) {
        return emplace(key, owned_object::make_boolean(std::forward<T>(value)));
    } else if constexpr (std::is_integral_v<std::remove_cvref_t<T>> &&
                         std::is_signed_v<std::remove_cvref_t<T>>) {
        return emplace(key, owned_object::make_signed(std::forward<T>(value)));
    } else if constexpr (std::is_integral_v<std::remove_cvref_t<T>> &&
                         std::is_unsigned_v<std::remove_cvref_t<T>>) {
        return emplace(key, owned_object::make_unsigned(std::forward<T>(value)));
    } else if constexpr (std::is_floating_point_v<std::remove_cvref_t<T>>) {
        return emplace(key, owned_object::make_float(std::forward<T>(value)));
    } else if constexpr (std::convertible_to<T, std::string_view>) {
        return emplace(
            key, owned_object::make_string(std::string_view(std::forward<T>(value)), alloc()));
    } else {
        return emplace(key, std::forward<T>(value));
    }
}

inline borrowed_object::borrowed_object(owned_object &obj) : obj_(obj.ptr()), alloc_(obj.alloc()) {}

// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
inline borrowed_object &borrowed_object::operator=(owned_object &&obj)
{
    if (this->obj_ == obj.ptr()) {
        return *this;
    }

    const bool moved_from_req_alloc = detail::requires_allocator(obj.type());

    // the borrowed_object is likely part of a larger owned_object, so we must
    // ensure that the allocators are the same for types that require allocation
    if (moved_from_req_alloc && !detail::alloc_equal(alloc_, obj.alloc())) {
        throw std::runtime_error("borrowed_object assignment: incompatible allocators");
    }

    {
        // destroy current object
        detail::object_destroy(*obj_, alloc_);
    }

    *obj_ = obj.move();
    return *this;
}

class object_cache_key {
public:
    object_cache_key() = default;
    // NOLINTBEGIN(google-explicit-constructor,hicpp-explicit-conversions)
    object_cache_key(object_view view) : ptr_(static_cast<const void *>(view.ptr())) {}
    object_cache_key(const owned_object &obj) : ptr_(static_cast<const void *>(obj.ptr())) {}
    object_cache_key(borrowed_object obj) : ptr_(static_cast<const void *>(obj.ptr())) {}
    // NOLINTEND(google-explicit-constructor,hicpp-explicit-conversions)

    bool operator==(const object_cache_key &other) const { return ptr_ == other.ptr_; }
    bool operator==(const object_view &other) const { return ptr_ == other.ptr(); }

    [[nodiscard]] std::size_t hash() const noexcept { return std::hash<const void *>{}(ptr_); }

private:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const void *ptr_{nullptr};
};

namespace object_builder {

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

using all_types = std::variant<bool, int16_t, int32_t, int64_t, uint16_t, uint32_t, uint64_t,
    double, const char *, std::string_view, std::string, movable_object>;
using key_value = std::pair<std::string_view, all_types>;

inline owned_object array(
    std::initializer_list<all_types> list, nonnull_ptr<memory::memory_resource> alloc)
{
    auto container = owned_object::make_array(static_cast<uint16_t>(list.size()), alloc);
    for (const auto &value : list) {
        if (std::holds_alternative<bool>(value)) {
            container.emplace_back(owned_object::make_boolean(std::get<bool>(value)));
        } else if (std::holds_alternative<int16_t>(value)) {
            container.emplace_back(owned_object::make_signed(std::get<int16_t>(value)));
        } else if (std::holds_alternative<uint16_t>(value)) {
            container.emplace_back(owned_object::make_unsigned(std::get<uint16_t>(value)));
        } else if (std::holds_alternative<int32_t>(value)) {
            container.emplace_back(owned_object::make_signed(std::get<int32_t>(value)));
        } else if (std::holds_alternative<uint32_t>(value)) {
            container.emplace_back(owned_object::make_unsigned(std::get<uint32_t>(value)));
        } else if (std::holds_alternative<int64_t>(value)) {
            container.emplace_back(owned_object::make_signed(std::get<int64_t>(value)));
        } else if (std::holds_alternative<uint64_t>(value)) {
            container.emplace_back(owned_object::make_unsigned(std::get<uint64_t>(value)));
        } else if (std::holds_alternative<double>(value)) {
            container.emplace_back(owned_object::make_float(std::get<double>(value)));
        } else if (std::holds_alternative<const char *>(value)) {
            container.emplace_back(owned_object::make_string(std::get<const char *>(value), alloc));
        } else if (std::holds_alternative<std::string_view>(value)) {
            container.emplace_back(
                owned_object::make_string(std::get<std::string_view>(value), alloc));
        } else if (std::holds_alternative<std::string>(value)) {
            container.emplace_back(owned_object::make_string(std::get<std::string>(value), alloc));
        } else {
            container.emplace_back(std::move(std::get<movable_object>(value).object));
        }
    }
    return container;
}

inline owned_object map(
    std::initializer_list<key_value> list, nonnull_ptr<memory::memory_resource> alloc)
{
    auto container = owned_object::make_map(static_cast<uint16_t>(list.size()), alloc);
    for (const auto &[key, value] : list) {
        if (std::holds_alternative<bool>(value)) {
            container.emplace(key, owned_object::make_boolean(std::get<bool>(value)));
        } else if (std::holds_alternative<int16_t>(value)) {
            container.emplace(key, owned_object::make_signed(std::get<int16_t>(value)));
        } else if (std::holds_alternative<uint16_t>(value)) {
            container.emplace(key, owned_object::make_unsigned(std::get<uint16_t>(value)));
        } else if (std::holds_alternative<int32_t>(value)) {
            container.emplace(key, owned_object::make_signed(std::get<int32_t>(value)));
        } else if (std::holds_alternative<uint32_t>(value)) {
            container.emplace(key, owned_object::make_unsigned(std::get<uint32_t>(value)));
        } else if (std::holds_alternative<int64_t>(value)) {
            container.emplace(key, owned_object::make_signed(std::get<int64_t>(value)));
        } else if (std::holds_alternative<uint64_t>(value)) {
            container.emplace(key, owned_object::make_unsigned(std::get<uint64_t>(value)));
        } else if (std::holds_alternative<double>(value)) {
            container.emplace(key, owned_object::make_float(std::get<double>(value)));
        } else if (std::holds_alternative<const char *>(value)) {
            container.emplace(key, owned_object::make_string(std::get<const char *>(value), alloc));
        } else if (std::holds_alternative<std::string_view>(value)) {
            container.emplace(
                key, owned_object::make_string(std::get<std::string_view>(value), alloc));
        } else if (std::holds_alternative<std::string>(value)) {
            container.emplace(key, owned_object::make_string(std::get<std::string>(value), alloc));
        } else {
            container.emplace(key, std::move(std::get<movable_object>(value).object));
        }
    }
    return container;
}

} // namespace object_builder

} // namespace ddwaf

namespace std {

template <> struct hash<ddwaf::object_cache_key> {
    auto operator()(const ddwaf::object_cache_key &key) const { return key.hash(); }
};
} // namespace std
