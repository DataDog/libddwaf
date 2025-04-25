// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "condition/base.hpp"
#include "iterator.hpp"
#include "traits.hpp"
#include "utils.hpp"

namespace ddwaf {

// A type of argument with a single address (target) mapping
template <typename T> struct unary_argument {
    // The memory associated with the address and the key path is owned
    // by either the condition (condition_target) or the processor (processor_target).
    std::string_view address{};
    std::span<const std::string> key_path;
    bool ephemeral{false};
    T value;
};

template <typename T, typename = void> struct is_unary_argument : std::false_type {};
template <typename T> struct is_unary_argument<unary_argument<T>> : std::true_type {};

// A type of argument which is considered to be optional
template <typename T> using optional_argument = std::optional<unary_argument<T>>;

template <typename T, typename = void> struct is_optional_argument : std::false_type {};
template <typename T> struct is_optional_argument<optional_argument<T>> : std::true_type {};

// A type of argument with multiple address(target) mappings
template <typename T> using variadic_argument = std::vector<unary_argument<T>>;

template <typename T, typename = void> struct is_variadic_argument : std::false_type {};
template <typename T> struct is_variadic_argument<variadic_argument<T>> : std::true_type {};

template <typename T> std::optional<T> convert(const ddwaf_object *obj)
{
    if constexpr (std::is_same_v<T, decltype(obj)>) {
        return obj;
    }

    if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>) {
        if (obj->type == DDWAF_OBJ_STRING) {
            return T{obj->stringValue, static_cast<std::size_t>(obj->nbEntries)};
        }
    }

    if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, unsigned>) {
        using limits = std::numeric_limits<T>;
        if (obj->type == DDWAF_OBJ_UNSIGNED && obj->uintValue <= limits::max()) {
            return static_cast<T>(obj->uintValue);
        }
    }

    if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, int>) {
        using limits = std::numeric_limits<T>;
        if (obj->type == DDWAF_OBJ_SIGNED && obj->intValue >= limits::min() &&
            obj->intValue <= limits::max()) {
            return static_cast<T>(obj->intValue);
        }
    }

    if constexpr (std::is_same_v<T, bool>) {
        if (obj->type == DDWAF_OBJ_BOOL) {
            return static_cast<T>(obj->boolean);
        }
    }

    return {};
}

struct default_argument_retriever {
    static constexpr bool is_variadic = false;
    static constexpr bool is_optional = false;
};

template <typename T> struct argument_retriever : default_argument_retriever {};

template <typename T> struct argument_retriever<unary_argument<T>> : default_argument_retriever {
    template <typename TargetType>
    static std::optional<unary_argument<T>> retrieve(const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const TargetType &target)
    {
        auto [object, attr] = store.get_target(target.index);
        if (object == nullptr || objects_excluded.contains(object)) {
            return std::nullopt;
        }

        if (!target.key_path.empty()) {
            object::value_iterator it{object, target.key_path, objects_excluded};

            if (!it) {
                return std::nullopt;
            }
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            object = const_cast<ddwaf_object *>(*it);
        }

        auto converted = convert<T>(object);
        if (!converted.has_value()) {
            return std::nullopt;
        }

        return unary_argument<T>{target.name, target.key_path,
            attr == object_store::attribute::ephemeral, std::move(converted.value())};
    }
};

template <typename T> struct argument_retriever<optional_argument<T>> : default_argument_retriever {
    static constexpr bool is_optional = true;

    template <typename TargetType>
    static optional_argument<T> retrieve(const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const TargetType &target)
    {
        return argument_retriever<unary_argument<T>>::retrieve(store, objects_excluded, target);
    }
};

template <typename T> struct argument_retriever<variadic_argument<T>> : default_argument_retriever {
    static constexpr bool is_variadic = true;

    template <typename TargetType>
    static variadic_argument<T> retrieve(const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const std::vector<TargetType> &targets)
    {
        variadic_argument<T> args;
        for (const auto &target : targets) {
            auto arg =
                argument_retriever<unary_argument<T>>::retrieve(store, objects_excluded, target);
            if (!arg.has_value()) {
                continue;
            }
            args.emplace_back(std::move(arg.value()));
        }
        return args;
    }
};

} // namespace ddwaf
