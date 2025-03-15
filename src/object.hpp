// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "ddwaf.h"
#include "object_type.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace ddwaf {

namespace detail {

using object = ddwaf_object;

inline char *copy_string(const char *str, std::size_t len)
{
    // TODO new char[len];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,hicpp-no-malloc)
    char *copy = static_cast<char *>(malloc(sizeof(char) * (len + 1)));
    if (copy == nullptr) {
        [[unlikely]] throw std::bad_alloc();
    }

    memcpy(copy, str, len);
    copy[len] = '\0';

    return copy;
}

inline void realloc_array(object &obj)
{
    const auto size = static_cast<std::size_t>(obj.nbEntries) + 8;
    if (size > SIZE_MAX / sizeof(object)) {
        throw std::bad_alloc();
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *new_array = reinterpret_cast<object *>(
        // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-pro-type-reinterpret-cast)
        realloc(reinterpret_cast<void *>(obj.array), size * sizeof(object)));
    if (new_array == nullptr) {
        throw std::bad_alloc();
    }

    obj.array = new_array;
}

inline void alloc_array(object &obj)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,hicpp-no-malloc)
    obj.array = reinterpret_cast<object *>(malloc(8 * sizeof(object)));
    if (obj.array == nullptr) {
        throw std::bad_alloc();
    }
}

} // namespace detail

class owned_object;
class borrowed_object;
class object_view;
class object_key;

template <typename Derived> class base_object {
public:
    [[nodiscard]] std::size_t size() const noexcept
    {
        return static_cast<std::size_t>(static_cast<const Derived *>(this)->ref().nbEntries);
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    [[nodiscard]] object_type type() const noexcept
    {
        return static_cast<object_type>(static_cast<const Derived *>(this)->ref().type);
    }

    // The is_* methods can be used to check for collections of types
    [[nodiscard]] bool is_container() const noexcept
    {
        return (type() & container_object_type) != 0;
    }

    [[nodiscard]] bool is_valid() const noexcept { return type() != object_type::invalid; }

    [[nodiscard]] bool is_invalid() const noexcept { return type() == object_type::invalid; }

    [[nodiscard]] borrowed_object at(std::size_t idx);

    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);

private:
    base_object() = default;
    friend Derived;
};

class owned_object;

class borrowed_object : public base_object<borrowed_object> {
public:
    borrowed_object() = default;
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
    detail::object *obj_{nullptr};

    friend class object_view;
};

class owned_object : public base_object<owned_object> {
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

    friend class base_object<borrowed_object>;
    friend class base_object<owned_object>;
    friend class object_view;
};

inline borrowed_object::borrowed_object(owned_object &obj) : obj_(obj.ptr()) {}

template <typename Derived> [[nodiscard]] borrowed_object base_object<Derived>::at(std::size_t idx)
{
    assert(is_container() && idx < size());
    auto &container = static_cast<const Derived *>(this)->ref();
    return borrowed_object{&container.array[idx]};
}

// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
template <typename Derived> borrowed_object base_object<Derived>::emplace_back(owned_object &&value)
{
    assert(is_container());

    auto &container = static_cast<Derived *>(this)->ref();

    // We preallocate 8 entries
    if (container.nbEntries == 0) {
        [[unlikely]] detail::alloc_array(container);
    }
    // If we're exceeding our preallocation, add 8 more
    else if ((container.nbEntries & 0x7) == 0) {
        detail::realloc_array(container);
    }

    auto *slot = &container.array[container.nbEntries++];
    memcpy(slot, value.ptr(), sizeof(detail::object));

    // The object has to be explicitly moved, otherwise the contents will be freed
    // on return, causing the inserted object to be invalid
    value.move();

    return borrowed_object{slot};
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object base_object<Derived>::emplace(std::string_view key, owned_object &&value)
{
    assert(is_container());

    auto &container = static_cast<Derived *>(this)->ref();

    // We preallocate 8 entries
    if (container.nbEntries == 0) {
        [[unlikely]] detail::alloc_array(container);
    }
    // If we're exceeding our preallocation, add 8 more
    else if ((container.nbEntries & 0x7) == 0) {
        detail::realloc_array(container);
    }

    auto *value_ptr = value.ptr();
    value_ptr->parameterName = detail::copy_string(key.data(), key.size());
    value_ptr->parameterNameLength = key.size();

    auto *slot = &container.array[container.nbEntries++];
    memcpy(slot, value.ptr(), sizeof(detail::object));

    // The object has to be explicitly moved, otherwise the contents will be freed
    // on return, causing the inserted object to be invalid
    value.move();

    return borrowed_object{slot};
}

} // namespace ddwaf
