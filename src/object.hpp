// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <memory_resource>
#include <string_view>

#include "object_type.hpp"

namespace ddwaf {

namespace detail {
constexpr std::size_t OBJ_SSTR_SIZE = 11;

struct object_kv;
struct [[gnu::packed, gnu::may_alias]] object {
    union [[gnu::packed]] {
        bool b8;
        uint64_t u64;
        int64_t i64;
        double f64;
        object_kv *map;
        object *array;
        char *str;
        const char *cstr;
        std::array<char, OBJ_SSTR_SIZE> sstr;
    } via;
    object_type type;
    union [[gnu::packed]] {
        struct [[gnu::packed]] {
            uint16_t capacity;
            uint16_t size;
        };
        uint32_t length;
    };
};

struct [[gnu::packed]] object_kv {
    detail::object key;
    detail::object val;
};

struct object_iterator {
    union {
        const object *ptr;
        const object_kv *kv_ptr;
    } via;
    uint16_t index;
    uint16_t size;
    object_type type;
    // 1 byte of padding to spare

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    static object_iterator construct(
        const detail::object *obj, std::size_t index, std::size_t max_size)
    {
        if (obj->type == object_type::array) {
            return {
                .via = {.ptr = obj->via.array},
                .index = index < obj->size ? index : obj->size,
                .size = obj->size < max_size ? obj->size : max_size,
                .type = object_type::array,
            };
        }
        if (obj->type == object_type::map) {
            return {
                .via = {.kv_ptr = obj->via.map},
                .index = index < obj->size ? index : obj->size,
                .size = obj->size < max_size ? obj->size : max_size,
                .type = object_type::map,
            };
        }

        return {
            .via = {.ptr = nullptr},
            .index = 0,
            .size = 0,
            .type = object_type::invalid,
        };
    }

    object_iterator &operator++() noexcept
    {
        if (index < size) {
            ++index;
        }
        return *this;
    }

    std::pair<const detail::object *, const detail::object *> operator*() const noexcept
    {
        if (index < size) {
            if (type == object_type::array) {
                return {nullptr, &via.ptr[index]};
            }

            if (type == object_type::map) {
                const auto &kv = via.kv_ptr[index];
                return {&kv.key, &kv.val};
            }
        }

        [[unlikely]] return {};
    }

    [[nodiscard]] bool is_valid() const noexcept { return index < size; }

    [[nodiscard]] const object *key() const noexcept
    {
        if (type == object_type::map) {
            return &via.kv_ptr[index].key;
        }
        return nullptr;
    }

    [[nodiscard]] const object *value() const noexcept
    {
        if (type == object_type::map) {
            return &via.kv_ptr[index].val;
        }
        if (type == object_type::array) {
            return &via.ptr[index];
        }
        return nullptr;
    }
};

// Assert that all detail types have the correct size and alignment
static_assert(sizeof(object) == 16);
//static_assert(alignof(object) == 16);

static_assert(sizeof(object_kv) == 32);
//static_assert(alignof(object_kv) == 32);

//static_assert(sizeof(object_iterator) == 13);
//static_assert(alignof(object_iterator) == 16);

// Assert that all detail types have a standard layout
static_assert(std::is_standard_layout_v<object>);
static_assert(std::is_standard_layout_v<object_kv>);
static_assert(std::is_standard_layout_v<object_iterator>);

// Assert that all detail types incur no construction, copy  or destruction overhead
static_assert(std::is_trivial_v<object>);
static_assert(std::is_trivial_v<object_kv>);
static_assert(std::is_trivial_v<object_iterator>);

// Allocation-related assertions to avoid further runtime checks later on
template <typename T> inline constexpr std::size_t maxof() { return std::numeric_limits<T>::max(); }

static_assert(maxof<std::size_t>() / sizeof(char) >= maxof<uint32_t>());
static_assert(maxof<std::size_t>() / sizeof(detail::object) >= maxof<uint16_t>());
static_assert(maxof<std::size_t>() / sizeof(detail::object_kv) >= maxof<uint16_t>());

// These helper work under some assumptions:
// - Static asserts above ensure that sizeof(T) * count never overflows, since these
//   are only meant to be used with sizeof(char), sizeof(object), sizeof(object_kv)
//   and count is limited.
// - The callers of these helper are enforcing said limits.
template <typename T> T *alloc_helper(auto &alloc, std::size_t count)
{
    if (count == 0) {
        [[unlikely]] return nullptr;
    }
    return static_cast<T *>(alloc.allocate(sizeof(T) * count, alignof(T)));
}

template <typename T> void dealloc_helper(auto &alloc, T *ptr, std::size_t count)
{
    if (ptr == nullptr) {
        [[unlikely]] return;
    }
    alloc.deallocate(static_cast<void *>(ptr), sizeof(T) * count, alignof(T));
}

template <typename T>
std::pair<T *, std::size_t> realloc_helper(auto &alloc, T *buffer, std::size_t count)
{
    if (count == 0) {
        return {alloc_helper<T>(alloc, 4), 4};
    }

    auto new_count = count * 2;
    T *new_buffer = alloc_helper<T>(alloc, new_count);
    std::memcpy(new_buffer, buffer, count * sizeof(T));
    dealloc_helper(alloc, buffer, count);

    return {new_buffer, new_count};
}

// TODO implement iterative
// NOLINTNEXTLINE(misc-no-recursion)
inline void object_destroy(detail::object &obj, std::pmr::memory_resource *alloc)
{
    if (obj.type == object_type::array) {
        for (std::size_t i = 0; i < obj.size; ++i) { object_destroy(obj.via.array[i], alloc); }
        dealloc_helper<detail::object>(*alloc, obj.via.array, obj.capacity);
    } else if (obj.type == object_type::map) {
        for (std::size_t i = 0; i < obj.size; ++i) {
            object_destroy(obj.via.map[i].key, alloc);
            object_destroy(obj.via.map[i].val, alloc);
        }
        dealloc_helper<detail::object_kv>(*alloc, obj.via.map, obj.capacity);
    } else if (obj.type == object_type::string) {
        dealloc_helper<char>(*alloc, obj.via.str, obj.length);
    }
}

inline void object_free(detail::object *ptr, std::pmr::memory_resource *alloc)
{
    object_destroy(*ptr, alloc);
    dealloc_helper<detail::object>(*alloc, ptr, 1);
}

struct object_deleter {
    explicit object_deleter(std::pmr::memory_resource *alloc) : alloc(alloc) {}
    void operator()(object *ptr) const { object_free(ptr, alloc); }
    std::pmr::memory_resource *alloc;
};

using object_uptr = std::unique_ptr<object, object_deleter>;

inline bool requires_allocator(object_type type)
{
    // Container or non-const, non-small, string
    return (type & container_object_type) != 0 || type == object_type::string;
}

} // namespace detail

class owned_object;
class borrowed_object;

template <typename Derived> class base_object {
public:
    [[nodiscard]] object_type type() const noexcept;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] bool is_invalid() const noexcept;
    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);
    borrowed_object emplace(owned_object &&key, owned_object &&value);
};

class owned_object;

class borrowed_object : public base_object<borrowed_object> {
public:
    borrowed_object() = default;
    explicit borrowed_object(
        detail::object *obj, std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
        : obj_(obj), alloc_(alloc)
    {}

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    [[nodiscard]] detail::object *ptr() { return obj_; }
    [[nodiscard]] const detail::object *ptr() const { return obj_; }
    [[nodiscard]] std::pmr::memory_resource *alloc() { return alloc_; }

protected:
    detail::object *obj_{nullptr};
    std::pmr::memory_resource *alloc_{nullptr};
};

class owned_object : public base_object<owned_object> {
public:
    using size_type = decltype(detail::object::size);
    using length_type = decltype(detail::object::length);

    static_assert(std::is_same_v<size_type, decltype(detail::object::capacity)>);

    owned_object() = default;
    explicit owned_object(
        detail::object obj, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
        : obj_(obj), alloc_(alloc)
    {}

    ~owned_object()
    {
        if (alloc_ != nullptr) {
            detail::object_destroy(obj_, alloc_);
        }
    }

    owned_object(const owned_object &) = delete;
    owned_object &operator=(const owned_object &) = delete;

    owned_object(owned_object &&other) noexcept : obj_(other.obj_), alloc_(other.alloc_)
    {
        other.obj_ = detail::object{};
        other.alloc_ = nullptr;
    }

    owned_object &operator=(owned_object &&other) noexcept
    {
        obj_ = other.obj_;
        alloc_ = other.alloc_;
        other.obj_ = detail::object{};
        other.alloc_ = nullptr;
        return *this;
    }

    [[nodiscard]] detail::object *ptr() { return &obj_; }
    [[nodiscard]] const detail::object *ptr() const { return &obj_; }
    [[nodiscard]] std::pmr::memory_resource *alloc() { return alloc_; }

    static owned_object make_null()
    {
        return owned_object{{.via = {{0}}, .type = object_type::null, .length = 0}, nullptr};
    }

    static owned_object make_boolean(bool value)
    {
        return owned_object{
            {.via = {.b8 = value}, .type = object_type::boolean, .length = 0}, nullptr};
    }

    static owned_object make_signed(int64_t value)
    {
        return owned_object{
            {.via = {.i64 = value}, .type = object_type::int64, .length = 0}, nullptr};
    }

    static owned_object make_unsigned(uint64_t value)
    {
        return owned_object{
            {.via = {.u64 = value}, .type = object_type::uint64, .length = 0}, nullptr};
    }

    static owned_object make_float(double value)
    {
        return owned_object{
            {.via = {.f64 = value}, .type = object_type::float64, .length = 0}, nullptr};
    }

    static owned_object make_const_string(const char *str, std::size_t len)
    {
        return make_const_string({str, len});
    }
    static owned_object make_const_string(std::string_view str)
    {
        if constexpr (sizeof(std::size_t) > sizeof(length_type)) {
            if (str.size() > std::numeric_limits<length_type>::max()) {
                return {};
            }
        }

        return owned_object{{.via = {.cstr = str.data()},
                                .type = object_type::const_string,
                                .length = static_cast<length_type>(str.size())},
            nullptr};
    }

    static owned_object make_string_nocopy(char *str, std::size_t len,
        std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        if constexpr (sizeof(std::size_t) > sizeof(length_type)) {
            if (len > std::numeric_limits<length_type>::max()) {
                return {};
            }
        }

        return owned_object{{.via = {.str = str},
                                .type = object_type::string,
                                .length = static_cast<length_type>(len)},
            alloc};
    }

    static owned_object make_string(const char *str, std::size_t len,
        std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        return make_string(std::string_view{str, len}, alloc);
    }

    static owned_object make_string(
        std::string_view str, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        if constexpr (sizeof(std::size_t) > sizeof(length_type)) {
            if (str.size() > std::numeric_limits<length_type>::max()) {
                return {};
            }
        }

        detail::object obj{};
        obj.length = str.size();

        if (str.size() <= detail::OBJ_SSTR_SIZE) {
            obj.type = object_type::small_string;
            if (str.data() != nullptr) {
                std::memcpy(&obj.via.sstr, str.data(), str.size());
            }
            return owned_object{obj, nullptr};
        }

        obj.type = object_type::string;
        obj.via.str = detail::alloc_helper<char>(*alloc, str.size());
        std::memcpy(obj.via.str, str.data(), str.size());
        return owned_object{obj, alloc};
    }

    static owned_object make_array(
        std::size_t capacity, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        if (capacity > std::numeric_limits<size_type>::max() || alloc == nullptr) {
            return {};
        }
        return owned_object{
            {.via = {.array = detail::alloc_helper<detail::object>(*alloc, capacity)},
                .type = object_type::array,
                .capacity = static_cast<size_type>(capacity),
                .size = 0},
            alloc};
    }

    static owned_object make_map(
        std::size_t capacity, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        if (capacity > std::numeric_limits<size_type>::max() || alloc == nullptr) {
            return {};
        }

        return owned_object{
            {.via = {.map = detail::alloc_helper<detail::object_kv>(*alloc, capacity)},
                .type = object_type::map,
                .capacity = static_cast<size_type>(capacity),
                .size = 0},
            alloc};
    }

    detail::object move()
    {
        detail::object copy = obj_;
        obj_ = detail::object{};
        return copy;
    }

protected:
    detail::object obj_{};
    std::pmr::memory_resource *alloc_{std::pmr::get_default_resource()};

    friend class base_object<borrowed_object>;
    friend class base_object<owned_object>;
};

template <typename Derived> [[nodiscard]] object_type base_object<Derived>::type() const noexcept
{
    return static_cast<const Derived *>(this)->ptr()->type;
}

template <typename Derived> [[nodiscard]] bool base_object<Derived>::is_valid() const noexcept
{
    auto obj = static_cast<const Derived *>(this)->ptr();
    return obj != nullptr && obj->type != object_type::invalid;
}

template <typename Derived> [[nodiscard]] bool base_object<Derived>::is_invalid() const noexcept
{
    auto obj = static_cast<const Derived *>(this)->ptr();
    return obj != nullptr && obj->type == object_type::invalid;
}

template <typename Derived> borrowed_object base_object<Derived>::emplace_back(owned_object &&value)
{
    auto obj = static_cast<Derived *>(this)->ptr();
    auto alloc = static_cast<Derived *>(this)->alloc();

    if (obj == nullptr || obj->type != object_type::array ||
        (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc)) {
        return {};
    }

    if (obj->size == obj->capacity) {
        auto [new_array, new_capacity] =
            detail::realloc_helper<detail::object>(*alloc, obj->via.array, obj->capacity);
        obj->via.array = new_array;
        obj->capacity = new_capacity;
    }

    auto &current = obj->via.array[obj->size++];
    current = value.move();
    return borrowed_object{&current, alloc};
}

template <typename Derived>
borrowed_object base_object<Derived>::emplace(std::string_view key, owned_object &&value)
{
    auto obj = static_cast<Derived *>(this)->ptr();
    auto alloc = static_cast<Derived *>(this)->alloc();

    if (obj == nullptr || obj->type != object_type::map ||
        (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc)) {
        return {};
    }

    if (obj->size == obj->capacity) {
        auto [new_map, new_capacity] =
            detail::realloc_helper<detail::object_kv>(*alloc, obj->via.map, obj->capacity);
        obj->via.map = new_map;
        obj->capacity = new_capacity;
    }

    auto &current = obj->via.map[obj->size++];
    current.key = owned_object::make_string(key, alloc).move();
    current.val = value.move();
    return borrowed_object{&current.val, alloc};
}

template <typename Derived>
borrowed_object base_object<Derived>::emplace(owned_object &&key, owned_object &&value)
{
    auto obj = static_cast<Derived *>(this)->ptr();
    auto alloc = static_cast<Derived *>(this)->alloc();

    if (obj == nullptr || obj->type != object_type::map ||
        (key.obj_.type & object_type::string) == 0 ||
        (detail::requires_allocator(key.obj_.type) && key.alloc_ != alloc) ||
        (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc)) {
        return {};
    }

    if (obj->size == obj->capacity) {
        auto [new_map, new_capacity] =
            detail::realloc_helper<detail::object_kv>(*alloc, obj->via.map, obj->capacity);
        obj->via.map = new_map;
        obj->capacity = new_capacity;
    }

    auto &current = obj->via.map[obj->size++];
    current.key = key.move();
    current.val = value.move();

    return borrowed_object{&current.val, alloc};
}

} // namespace ddwaf
