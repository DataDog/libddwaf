// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "ddwaf.h"
#include "object_type.hpp"
#include <stdexcept>

namespace ddwaf {

namespace detail {

using object = ddwaf_object;

} // namespace detail

class owned_object;
class borrowed_object;

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

    [[nodiscard]] bool is_valid() const noexcept { return type() != object_type::invalid; }

    [[nodiscard]] bool is_invalid() const noexcept { return type() == object_type::invalid; }

    [[nodiscard]] borrowed_object at(std::size_t idx);

    borrowed_object emplace_back(owned_object &&value);
    borrowed_object emplace(std::string_view key, owned_object &&value);
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
        detail::object tmp;
        ddwaf_object_stringl_nc(&tmp, str, len);
        return owned_object{tmp, free_fn};
    }

    static owned_object make_string_nocopy(
        std::string_view str, ddwaf_object_free_fn free_fn = ddwaf_object_free)
    {
        return make_string_nocopy(str.data(), str.size(), free_fn);
    }

    static owned_object make_string(const char *str, std::size_t len)
    {
        detail::object tmp;
        ddwaf_object_stringl(&tmp, str, len);
        return owned_object{tmp};
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
        detail::object tmp;
        ddwaf_object_array(&tmp);
        return owned_object{tmp};
    }

    static owned_object make_map()
    {
        detail::object tmp;
        ddwaf_object_map(&tmp);
        return owned_object{tmp};
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

template <typename Derived> [[nodiscard]] borrowed_object base_object<Derived>::at(std::size_t idx)
{
    auto *container = static_cast<const Derived *>(this)->ptr();
    auto *value = const_cast<detail::object *>(ddwaf_object_get_index(container, idx));
    if (value == nullptr) {
        throw std::out_of_range("invalid at() access");
    }
    return borrowed_object{value};
}

template <typename Derived> borrowed_object base_object<Derived>::emplace_back(owned_object &&value)
{
    auto *container = static_cast<Derived *>(this)->ptr();

    if (!ddwaf_object_array_add(container, value.ptr())) {
        throw std::out_of_range("failed to emplace_back value to container");
    }

    value.move();
    return borrowed_object{&container->array[container->nbEntries - 1]};
}

template <typename Derived>
borrowed_object base_object<Derived>::emplace(std::string_view key, owned_object &&value)
{
    auto *container = static_cast<Derived *>(this)->ptr();

    if (!ddwaf_object_map_addl(container, key.data(), key.size(), value.ptr())) {
        throw std::out_of_range("failed to emplace value to container");
    }

    value.move();
    return borrowed_object{&container->array[container->nbEntries - 1]};
}

} // namespace ddwaf
