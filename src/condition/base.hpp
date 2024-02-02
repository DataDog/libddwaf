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
#include <vector>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
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
    event::match match;
};

// Provides the specification of a specific operator parameter. Note that the
// type of the parameter is inferred at compile type.
struct parameter_specification {
    std::string_view name;
    bool variadic{false};
    bool optional{false};
};

// Provides the definition of an individual address(target) to parameter mapping.
// Each target must satisfy the associated parameter specification.
struct target_definition {
    std::string name;
    target_index root{};
    std::vector<std::string> key_path{};
    std::vector<transformer_id> transformers{};
    data_source source{data_source::values};
};

// Provides the definition of a parameter, which essentially consists of all the
// mappings available for it. If the parameter is non-variadic, only one mapping
// should be present.
struct parameter_definition {
    std::vector<target_definition> targets;
};

// A type of argument with a single address (target) mapping
template <typename T> struct unary_argument {
    std::string_view address{};
    std::span<const std::string> key_path;
    bool ephemeral{false};
    T value;
};

template <typename T, typename Enable = void> struct is_unary_argument : std::false_type {};
template <typename T> struct is_unary_argument<unary_argument<T>> : std::true_type {};

// A type of argument which is considered to be optional
template <typename T> using optional_argument = std::optional<unary_argument<T>>;

template <typename T, typename Enable = void> struct is_optional_argument : std::false_type {};
template <typename T> struct is_optional_argument<optional_argument<T>> : std::true_type {};

// A type of argument with multiple address(target) mappings
template <typename T> using variadic_argument = std::vector<unary_argument<T>>;

template <typename T, typename Enable = void> struct is_variadic_argument : std::false_type {};
template <typename T> struct is_variadic_argument<variadic_argument<T>> : std::true_type {};

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

template <typename T> struct argument_retriever<unary_argument<T>> : default_argument_retriever {
    static std::optional<unary_argument<T>> retrieve(
        const object_store &store, const target_definition &target)
    {
        auto [object, attr] = store.get_target(target.root);
        if (object == nullptr) {
            return std::nullopt;
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
    static optional_argument<T> retrieve(const object_store &store, const target_definition &target)
    {
        return argument_retriever<unary_argument<T>>::retrieve(store, target);
    }
};

template <typename T> struct argument_retriever<variadic_argument<T>> : default_argument_retriever {
    static constexpr bool is_variadic = true;
    static variadic_argument<T> retrieve(
        const object_store &store, const std::vector<target_definition> &targets)
    {
        variadic_argument<T> args;
        for (const auto &target : targets) {
            auto arg = argument_retriever<unary_argument<T>>::retrieve(store, target);
            if (!arg.has_value()) {
                continue;
            }
            args.emplace_back(std::move(arg.value()));
        }
        return args;
    }
};

// Generate a tuple containing a subset of the arguments
// Reference: https://stackoverflow.com/questions/71301988
template <typename... Ts> struct typelist;

template <size_t N, typename, typename> struct make_n_typelist;

template <typename Keep, typename Drop> struct make_n_typelist<0, Keep, Drop> {
    using type = Keep;
};

template <size_t N, typename K, typename... Ks, typename... Ds>
    requires(N > 0)
struct make_n_typelist<N, typelist<Ks...>, typelist<K, Ds...>> {
    using type = typename make_n_typelist<N - 1, typelist<Ks..., K>, typelist<Ds...>>::type;
};

template <size_t N, typename... Ts>
using make_n_typelist_t = typename make_n_typelist<N, typelist<>, typelist<Ts...>>::type;

template <typename... Ts> struct tuple_from_typelist;

template <typename... Ts> struct tuple_from_typelist<typelist<Ts...>> {
    using type = std::tuple<std::remove_cv_t<std::remove_reference_t<Ts>>...>;
};

template <size_t N, typename... Args>
using n_tuple_from_args_t = typename tuple_from_typelist<make_n_typelist_t<N, Args...>>::type;

// Function traits
template <typename Class, typename... Args> struct eval_function_traits {
    using tuple_type = n_tuple_from_args_t<Class::param_names.size(), Args...>;
    static inline constexpr size_t nargs = std::tuple_size_v<tuple_type>;
    template <size_t I> using arg_type = std::tuple_element_t<I, tuple_type>;
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
    explicit base_impl(std::vector<parameter_definition> args) : arguments_(std::move(args)) {}
    ~base_impl() override = default;
    base_impl(const base_impl &) = default;
    base_impl &operator=(const base_impl &) = default;
    base_impl(base_impl &&) noexcept = default;
    base_impl &operator=(base_impl &&) noexcept = default;

    [[nodiscard]] eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref & /*objects_excluded*/,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>>
            & /*dynamic_matchers*/,
        const object_limits & /*limits*/, ddwaf::timer &deadline) const override
    {

        using func_traits = decltype(make_traits(&Self::eval_impl));
        typename func_traits::tuple_type args;

        static_assert(func_traits::nargs == Self::param_names.size());

        if (!resolve_arguments(store, args, std::make_index_sequence<func_traits::nargs>{})) {
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
        return generate_argument_spec(std::make_index_sequence<Self::param_names.size()>());
    }

    template <size_t... Is>
    static constexpr auto generate_argument_spec(std::index_sequence<Is...>) // NOLINT
    {
        constexpr auto param_names = Self::param_names;
        using func_traits = decltype(make_traits(&Self::eval_impl));
        static_assert(param_names.size() <= func_traits::nargs);

        return std::array<parameter_specification, sizeof...(Is)>{{
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
    bool resolve_arguments(
        const object_store &store, Args &args, std::index_sequence<I, Is...> /*unused*/) const
    {
        using TupleElement = std::tuple_element_t<I, Args>;
        auto arg = resolve_argument<I>(store);
        if constexpr (is_unary_argument<TupleElement>::value) {
            if (!arg.has_value()) {
                return false;
            }

            std::get<I>(args) = std::move(arg.value());
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

    template <size_t I> auto resolve_argument(const object_store &store) const
    {
        using func_traits = decltype(make_traits(&Self::eval_impl));
        using target_type = typename func_traits::template arg_type<I>;

        using retriever = argument_retriever<target_type>;
        if constexpr (retriever::is_variadic) {
            if (arguments_.size() <= I) {
                return target_type{};
            }
            return retriever::retrieve(store, arguments_[I].targets);
        } else {
            if (arguments_.size() <= I) {
                return std::optional<target_type>{};
            }

            const auto &arg = arguments_[I];
            if (arg.targets.empty()) {
                return std::optional<target_type>{};
            }
            return retriever::retrieve(store, arg.targets.at(0));
        }
    }

    std::vector<parameter_definition> arguments_;
};

} // namespace ddwaf::condition
