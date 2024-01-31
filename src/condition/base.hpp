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

struct cache_type {
    // The targets cache mirrors the array of targets for the given condition.
    // Each element in this array caches the pointer of the last non-ephemeral
    // object evaluated by the target in the same index within the condition.
    memory::vector<const ddwaf_object *> targets;
    std::optional<event::match> match;
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

template <typename T> std::optional<T> convert(const ddwaf_object *obj)
{
    if constexpr (std::is_same_v<T, decltype(obj)>) {
        return obj;
    } else if constexpr (std::is_same_v<T, std::string_view>) {
        if (obj->type == DDWAF_OBJ_STRING) {
            return T{obj->stringValue, static_cast<std::size_t>(obj->nbEntries)};
        } 
    }
    return {};
}

template <typename T> struct argument_retriever : default_argument_retriever {};

template <typename T> struct argument_retriever<argument<T>> : default_argument_retriever {
    static std::variant<argument<T>, std::monostate> retrieve(
            const object_store &store, const target_definition &target)
    {
        auto [object, attr] = store.get_target(target.root);
        if (object == nullptr) {
            return {};
        }

        auto converted = convert<T>(object);
        if (!converted.has_value()) {
            return {};
        }

        return argument<T>{target.name, target.key_path, attr == object_store::attribute::ephemeral,
            std::move(converted.value())};
    }
};

template <typename T> struct argument_retriever<optional_argument<T>> : default_argument_retriever {
    static constexpr bool is_optional = true;
    static optional_argument<T> retrieve(const object_store &store, const target_definition &target)
    {
        auto arg = argument_retriever<argument<T>>::retrieve(store, target);
        if (std::holds_alternative<std::monostate>(arg)) {
            return {};
        }
        return std::move(std::get<argument<T>>(arg));
    }
};

template <typename T> struct argument_retriever<variadic_argument<T>> : default_argument_retriever {
    static constexpr bool is_variadic = true;
    static variadic_argument<T> retrieve(
        const object_store &store, const std::vector<target_definition> &targets)
    {
        variadic_argument<T> args;
        for (const auto &target : targets) {
            auto arg = argument_retriever<argument<T>>::retrieve(store, target);
            if (std::holds_alternative<std::monostate>(arg)) {
                continue;
            }
            args.emplace_back(std::move(std::get<argument<T>>(arg)));
        }

        return args;
    }
};


template <typename T, typename Enable = void>
struct is_argument : std::false_type {};

template <typename T>
struct is_argument<argument<T>> : std::true_type {};

template <typename T, typename Enable = void>
struct is_variadic_argument : std::false_type {};

template <typename T>
struct is_variadic_argument<variadic_argument<T>> : std::true_type {};


template <typename Class, typename... Args> struct eval_function_traits {
    using function_type = eval_result (Class::*)(Args...) const;
    static inline constexpr size_t nargs = sizeof...(Args);
    template <size_t I> using arg_type = std::tuple_element_t<I, std::tuple<Args...>>;
    using tuple_type = std::tuple<Args...>;
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
        const exclusion::object_set_ref & /*objects_excluded*/,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>>
            & /*dynamic_matchers*/,
        const object_limits &/*limits*/, ddwaf::timer &deadline) const override
    {
        typename Self::param_types args;
        static constexpr auto params_n = std::tuple_size_v<typename Self::param_types>;

        static_assert(params_n == Self::param_names.size());

        if (!resolve_arguments(store, args, std::make_index_sequence<params_n>{})) {
            return {};
        }

        // static_assert(sizeof(decltype(args)) == 0);
        return std::apply(
            [&](auto &&...args) {
                return static_cast<const Self *>(this)->eval_impl(
                    std::forward<decltype(args)>(args)..., cache, deadline);
            },
            std::move(args));
    }

    static constexpr auto arguments()
    {
        constexpr auto param_names = Self::param_names;
        return generate_argument_spec(std::make_index_sequence<param_names.size()>());
    }

    template <size_t... Is>
    static constexpr auto generate_argument_spec(std::index_sequence<Is...>) // NOLINT
    {
        constexpr auto param_names = Self::param_names;
        using func_traits = decltype(make_traits(&Self::eval_impl));
        static_assert(param_names.size() <= func_traits::nargs);
        return std::array<argument_specification, sizeof...(Is)>{{
            {
                param_names[Is],
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
    template <size_t I, size_t... Is, typename Args>
    bool resolve_arguments(const object_store &store, Args &args,
            std::index_sequence<I, Is...> /*unused*/) const
    {
        using TupleElement = std::tuple_element_t<I, Args>;
        auto arg = resolve_argument<I>(store);
        if constexpr (is_argument<TupleElement>::value) {
            if (std::holds_alternative<std::monostate>(arg)) {
                return false;
            }

            std::get<I>(args) = std::move(std::get<TupleElement>(arg));
        } else if constexpr (is_variadic_argument<TupleElement>::value) {
            if (arg.empty()) {
                return false;
            }

            std::get<I>(args) = std::move(arg);
        } else {
            std::get<I>(args) = std::move(arg);
        }

        if constexpr (sizeof...(Is) > 0) {
            return resolve_arguments(store, args, std::index_sequence<Is...>{});
        } else {
            return true;
        }

    }

    template <size_t I>
    auto resolve_argument(const object_store &store) const
    {
        using target_type = std::tuple_element_t<I, typename Self::param_types>;

        using retriever = argument_retriever<target_type>;
        if constexpr (retriever::is_variadic) {
            return retriever::retrieve(store, arguments_.at(I).targets);
        } else {
            return retriever::retrieve(store, arguments_.at(I).targets.at(0));
        }
    }

    std::vector<argument_definition> arguments_;
};

} // namespace ddwaf::condition
