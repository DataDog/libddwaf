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
        std::array<char, OBJ_SSTR_SIZE> sstr;
        bool b8;
        uint64_t u64;
        int64_t i64;
        double f64;
        object_kv *map;
        object *array;
        char *str;
        const char *cstr{nullptr};
    } via{{0}};
    object_type type{object_type::invalid};
    union [[gnu::packed]] {
        struct [[gnu::packed]] {
            uint16_t capacity{0};
            uint16_t size{0};
        };
        uint32_t length;
    };
};

struct [[gnu::packed]] object_kv {
    detail::object key;
    detail::object val;
};

static_assert(sizeof(object) == 16);
static_assert(sizeof(object_kv) == 32);

static_assert(
    std::numeric_limits<std::size_t>::max() / sizeof(char) >= std::numeric_limits<uint32_t>::max());
static_assert(std::numeric_limits<std::size_t>::max() / sizeof(detail::object) >=
              std::numeric_limits<uint16_t>::max());
static_assert(std::numeric_limits<std::size_t>::max() / sizeof(detail::object_kv) >=
              std::numeric_limits<uint16_t>::max());

inline object *object_alloc(std::pmr::memory_resource *alloc)
{
    auto *obj = static_cast<object *>(alloc->allocate(sizeof(object), alignof(object)));
    return new (obj) object{};
}

// TODO implement iterative
// NOLINTNEXTLINE(misc-no-recursion)
inline void object_destroy(detail::object &obj, std::pmr::memory_resource *alloc)
{
    if (obj.type == object_type::array) {
        for (std::size_t i = 0; i < obj.size; ++i) { object_destroy(obj.via.array[i], alloc); }
        alloc->deallocate(
            obj.via.array, obj.capacity * sizeof(detail::object), alignof(detail::object));
    } else if (obj.type == object_type::map) {
        for (std::size_t i = 0; i < obj.size; ++i) {
            object_destroy(obj.via.map[i].key, alloc);
            object_destroy(obj.via.map[i].val, alloc);
        }
        alloc->deallocate(
            obj.via.map, obj.capacity * sizeof(detail::object_kv), alignof(detail::object_kv));
    } else if (obj.type == object_type::string) {
        alloc->deallocate(obj.via.str, obj.length * sizeof(char));
    }
}

inline void object_free(detail::object *ptr, std::pmr::memory_resource *alloc)
{
    object_destroy(*ptr, alloc);
    alloc->deallocate(ptr, sizeof(detail::object), alignof(detail::object));
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

class borrowed_object {
public:
    borrowed_object() = default;
    explicit borrowed_object(
        detail::object *obj, std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
        : obj_(obj), alloc_(alloc)
    {}

    [[nodiscard]] bool has_value() const noexcept { return obj_ != nullptr; }

    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);
    borrowed_object emplace(owned_object &&key, owned_object &&value);

    [[nodiscard]] detail::object *ptr() const { return obj_; }

protected:
    detail::object *obj_{nullptr};
    std::pmr::memory_resource *alloc_{nullptr};

    friend class owned_object;
};

class owned_object {
public:
    using size_type = decltype(detail::object::size);
    using length_type = decltype(detail::object::length);

    static_assert(std::is_same_v<size_type, decltype(detail::object::capacity)>);

    owned_object() = default;
    explicit owned_object(
        detail::object obj, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
        : obj_(obj), alloc_(alloc)
    {}

    ~owned_object() { detail::object_destroy(obj_, alloc_); }

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

    [[nodiscard]] const detail::object *ptr() const { return &obj_; }

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
            std::memcpy(&obj.via.sstr, str.data(), str.size());
            return owned_object{obj, nullptr};
        }

        obj.type = object_type::string;
        obj.via.str = static_cast<char *>(alloc->allocate(sizeof(char) * str.size()));
        std::memcpy(obj.via.str, str.data(), str.size());
        return owned_object{obj, alloc};
    }

    static owned_object make_array(
        std::size_t capacity, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        if (capacity > std::numeric_limits<size_type>::max()) {
            return {};
        }
        return owned_object{
            {.via =
                    {
                        .array = static_cast<detail::object *>(alloc->allocate(
                            sizeof(detail::object) * capacity, alignof(detail::object))),
                    },
                .type = object_type::array,
                .capacity = static_cast<size_type>(capacity),
                .size = 0},
            alloc};
    }

    static owned_object make_map(
        std::size_t capacity, std::pmr::memory_resource *alloc = std::pmr::get_default_resource())
    {
        if (capacity > std::numeric_limits<size_type>::max()) {
            return {};
        }

        return owned_object{
            {.via = {.map = static_cast<detail::object_kv *>(alloc->allocate(
                         sizeof(detail::object_kv) * capacity, alignof(detail::object_kv)))},
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

    borrowed_object emplace_back(owned_object &&value)
    {
        if (obj_.type != object_type::array || obj_.size == obj_.capacity ||
            (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc_)) {
            return {};
        }

        auto &current = obj_.via.array[obj_.size++];
        current = value.move();
        return borrowed_object{&current, alloc_};
    }

    borrowed_object emplace(std::string_view key, owned_object &&value)
    {
        if (obj_.type != object_type::map || obj_.size == obj_.capacity ||
            (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc_)) {
            return {};
        }

        auto &current = obj_.via.map[obj_.size++];
        current.key = make_string(key).move();
        current.val = value.move();

        return borrowed_object{&current.val, alloc_};
    }

    borrowed_object emplace(owned_object &&key, owned_object &&value)
    {
        if (obj_.type != object_type::map || obj_.size == obj_.capacity ||
            (key.obj_.type & object_type::string) == 0 ||
            (detail::requires_allocator(key.obj_.type) && key.alloc_ != alloc_) ||
            (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc_)) {
            return {};
        }

        auto &current = obj_.via.map[obj_.size++];
        current.key = key.move();
        current.val = value.move();

        return borrowed_object{&current.val, alloc_};
    }

protected:
    friend class borrowed_object;

    detail::object obj_{};
    std::pmr::memory_resource *alloc_{std::pmr::get_default_resource()};
};

inline borrowed_object borrowed_object::emplace_back(owned_object &&value)
{
    if (obj_->type != object_type::array || obj_->size == obj_->capacity ||
        (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc_)) {
        return {};
    }

    auto &current = obj_->via.array[obj_->size++];
    current = value.move();
    return borrowed_object{&current, alloc_};
}

inline borrowed_object borrowed_object::emplace(std::string_view key, owned_object &&value)
{
    if (obj_->type != object_type::map || obj_->size == obj_->capacity ||
        (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc_)) {
        return {};
    }

    auto &current = obj_->via.map[obj_->size++];
    current.key = owned_object::make_string(key, alloc_).move();
    current.val = value.move();
    return borrowed_object{&current.val, alloc_};
}

inline borrowed_object borrowed_object::emplace(owned_object &&key, owned_object &&value)
{
    if (obj_->type != object_type::map || obj_->size == obj_->capacity ||
        (key.obj_.type & object_type::string) == 0 ||
        (detail::requires_allocator(key.obj_.type) && key.alloc_ != alloc_) ||
        (detail::requires_allocator(value.obj_.type) && value.alloc_ != alloc_)) {
        return {};
    }

    auto &current = obj_->via.map[obj_->size++];
    current.key = key.move();
    current.val = value.move();

    return borrowed_object{&current.val, alloc_};
}

} // namespace ddwaf
