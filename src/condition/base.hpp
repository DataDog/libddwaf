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
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"

namespace ddwaf::condition {

enum class data_source : uint8_t { values, keys, object };

enum class object_type : uint8_t {
    boolean = DDWAF_OBJ_BOOL,
    integer = DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED,
    real = DDWAF_OBJ_FLOAT,
    string = DDWAF_OBJ_STRING,
    array = DDWAF_OBJ_ARRAY,
    map = DDWAF_OBJ_MAP,
    container = map | array,
    scalar = boolean | integer | real | string,
    any = container | scalar,
};

struct cache_type {
    // The targets cache mirrors the array of targets for the given condition.
    // Each element in this array caches the pointer of the last non-ephemeral
    // object evaluated by the target in the same index within the condition.
    memory::vector<const ddwaf_object *> targets;
    std::optional<event::match> match;
};

enum class target_error {
    unavailable,
    invalid_type,
};

struct argument_specification {
    std::string_view name;
    bool variadic{false};
    bool optional{false};
};

// Provides the definition of the arguments for an instance of the condition,
// each argument definition must satisfy the argument specification.
struct target_definition {
    std::string name;
    target_index root{};
    std::vector<std::string> key_path{};
    std::vector<transformer_id> transformers{};
    data_source source{data_source::values};
};

struct argument_definition {
    std::vector<target_definition> targets;
};

template <typename Char, Char... Cs> struct constexpr_string {
    constexpr constexpr_string() noexcept = default;
    static constexpr size_t length() noexcept { return sizeof...(Cs); }
    constexpr operator const Char *() const noexcept { return value; }
    constexpr static const Char value[]{Cs..., 0};
};

// NOLINTNEXTLINE
template <typename Char, Char... Cs> constexpr auto operator""_cs() -> constexpr_string<Char, Cs...>
{
    return {};
}

template <const char *...Names> struct param_names_spec {
    static constexpr size_t size() { return sizeof...(Names); }
    static constexpr std::array<std::string_view, sizeof...(Names)> names = {Names...};
    template <size_t I> static constexpr std::string_view get()
    {
        static_assert(I < sizeof...(Names), "Index out of bounds");
        return std::get<I>(names);
    }
};

template <typename T> struct argument {
    std::string_view address{};
    std::span<const std::string> key_path;
    bool ephemeral{false};
    T value;
};

template <typename T> using optional_argument = std::optional<argument<T>>;

template <typename T> using variadic_argument = std::vector<argument<T>>;

struct default_argument_retriever {
    static constexpr bool is_variadic = false;
    static constexpr bool is_optional = false;
};

template <typename T> T convert(const ddwaf_object *obj)
{
    if constexpr (std::is_same_v<T, decltype(obj)>) {
        return obj;
    } else if constexpr (std::is_same_v<T, std::string_view>) {
        if (obj->type == DDWAF_OBJ_STRING) {
            return {obj->stringValue, static_cast<std::size_t>(obj->nbEntries)};
        } else {
            throw ddwaf::bad_cast("string", "unknown");
        }
    }
}

template <typename T> struct argument_retriever : default_argument_retriever {};

template <typename T> struct argument_retriever<argument<T>> : default_argument_retriever {
    static argument<T> retrieve(const object_store &store, const target_definition &target)
    {
        auto [object, attr] = store.get_target(target.root);
        if (object == nullptr) {
            throw std::runtime_error("object not available");
        }

        return {target.name, target.key_path, attr == object_store::attribute::ephemeral,
            convert<T>(object)};
    }
};

template <typename T> struct argument_retriever<optional_argument<T>> : default_argument_retriever {
    static constexpr bool is_optional = true;
    static optional_argument<T> retrieve(const object_store &store, const target_definition &target)
    {
        try {
            return argument_retriever<argument<T>>::retrieve(store, target);
        } catch (...) {
            return std::nullopt;
        }
    }
};

template <typename T> struct argument_retriever<variadic_argument<T>> : default_argument_retriever {
    static constexpr bool is_variadic = true;
    static variadic_argument<T> retrieve(
        const object_store &store, const std::vector<target_definition> &targets)
    {
        variadic_argument<T> args;
        for (const auto &target : targets) {
            try {
                args.emplace_back(argument_retriever<argument<T>>::retrieve(store, target));
            } catch (...) {
                // Variadic arguments can be ignored if not present
            }
        }

        if (args.empty()) {
            throw std::runtime_error("Argument unavailable");
        }

        return args;
    }
};

template <typename Class, typename... Args> struct eval_function_traits {
    using function_type = eval_result (Class::*)(Args...) const;
    static inline constexpr size_t nargs = sizeof...(Args);
    template <size_t I> using arg_type = std::tuple_element_t<I, std::tuple<Args...>>;
};

template <typename Class, typename... Args>
eval_function_traits<Class, Args...> make_traits(eval_result (Class::*)(Args...) const);

class base {
public:
    base() = default;
    virtual ~base() = default;
    base(const base &) = default;
    base &operator=(const base &) = default;
    base(base &&) = default;
    base &operator=(base &&) = default;

    virtual eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline) const = 0;

    virtual void get_addresses(std::unordered_map<target_index, std::string> &addresses) const = 0;
};

template <typename Self> class base_impl : public base {
public:
    explicit base_impl(std::vector<argument_definition> args) : arguments_(std::move(args)) {}
    ~base_impl() override = default;
    base_impl(const base_impl &) = default;
    base_impl &operator=(const base_impl &) = default;
    base_impl(base_impl &&) noexcept = default;
    base_impl &operator=(base_impl &&) noexcept = default;

    [[nodiscard]] eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>>
            & /*dynamic_matchers*/,
        const object_limits &limits, ddwaf::timer &deadline) const override
    {
        using func_traits = decltype(make_traits(&Self::eval_impl));
        auto &&args = resolve_arguments(cache, store, objects_excluded, limits, deadline,
            std::make_index_sequence<func_traits::nargs>{});
        // static_assert(sizeof(decltype(args)) == 0);
        return std::apply(
            [this, &cache](auto &&...args) {
                return static_cast<const Self *>(this)->eval_impl(
                    std::forward<decltype(args)>(args)...);
            },
            std::move(args));
    }

    static constexpr auto arguments()
    {
        constexpr auto param_names = typename Self::param_names{};
        return generate_argument_spec(std::make_index_sequence<param_names.size()>());
    }

    template <size_t... Is>
    static constexpr auto generate_argument_spec(std::index_sequence<Is...>) // NOLINT
    {
        constexpr auto param_names = typename Self::param_names{};
        using func_traits = decltype(make_traits(&Self::eval_impl));
        return std::array<argument_specification, sizeof...(Is)>{{
            {
                param_names.template get<Is>(),
                argument_retriever<typename func_traits::template arg_type<Is>>::is_optional,
                argument_retriever<typename func_traits::template arg_type<Is>>::is_variadic,
            }...,
        }};
    }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const override
    {
        for (const auto &arg : arguments_) {
            for (const auto &target : arg.targets) { addresses.emplace(target.root, target.name); }
        }
    }

protected:
    template <size_t... Is>
    auto resolve_arguments(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
        ddwaf::timer &deadline, std::index_sequence<Is...> /*unused*/) const
    {
        return std::tuple{
            resolve_argument<Is>(cache, store, objects_excluded, limits, deadline)...};
    }

    template <size_t I>
    auto resolve_argument(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
        ddwaf::timer &deadline) const
    {
        using func_traits = decltype(make_traits(&Self::eval_impl));
        using target_type = typename func_traits::template arg_type<I>;

        using retriever = argument_retriever<target_type>;
        if constexpr (std::is_same_v<target_type, std::reference_wrapper<cache_type>>) {
            return std::reference_wrapper{cache};
        } else if constexpr (std::is_same_v<target_type, decltype(objects_excluded)>) {
            return objects_excluded;
        } else if constexpr (std::is_same_v<target_type, decltype(limits)>) {
            return limits;
        } else if constexpr (std::is_same_v<target_type, std::reference_wrapper<timer>>) {
            return std::reference_wrapper<timer>{deadline};
        } else if constexpr (retriever::is_variadic) {
            return retriever::retrieve(store, arguments_.at(I).targets);
        } else {
            return retriever::retrieve(store, arguments_.at(I).targets.at(0));
        }
    }

    std::vector<argument_definition> arguments_;
};

} // namespace ddwaf::condition
