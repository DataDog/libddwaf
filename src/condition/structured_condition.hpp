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
#include "traits.hpp"
#include "utils.hpp"

namespace ddwaf {

// A type of argument with a single address (target) mapping
template <typename T> struct unary_argument {
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

struct default_argument_retriever {
    static constexpr bool is_variadic = false;
    static constexpr bool is_optional = false;
};

template <typename T> struct argument_retriever : default_argument_retriever {};

template <typename T> struct argument_retriever<unary_argument<T>> : default_argument_retriever {
    static std::optional<unary_argument<T>> retrieve(const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const target_definition &target)
    {
        auto [object, attr] = store.get_target_view(target.root);
        if (object == nullptr || objects_excluded.contains(object)) {
            return std::nullopt;
        }

        auto converted = object.as<T>();
        if (!converted.has_value()) {
            return std::nullopt;
        }

        return unary_argument<T>{target.name, target.key_path,
            attr == object_store::attribute::ephemeral, std::move(converted.value())};
    }
};

template <typename T> struct argument_retriever<optional_argument<T>> : default_argument_retriever {
    static constexpr bool is_optional = true;
    static optional_argument<T> retrieve(const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const target_definition &target)
    {
        return argument_retriever<unary_argument<T>>::retrieve(store, objects_excluded, target);
    }
};

template <typename T> struct argument_retriever<variadic_argument<T>> : default_argument_retriever {
    static constexpr bool is_variadic = true;
    static variadic_argument<T> retrieve(const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::vector<target_definition> &targets)
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

template <typename Class, typename... Args>
function_traits<Class::param_names.size(), Class, Args...> make_eval_traits(
    eval_result (Class::*)(Args...) const);

template <typename Self> class base_impl : public base_condition {
public:
    explicit base_impl(std::vector<parameter_definition> args, const object_limits &limits)
        : arguments_(std::move(args)), limits_(limits)
    {}
    ~base_impl() override = default;
    base_impl(const base_impl &) = default;
    base_impl &operator=(const base_impl &) = default;
    base_impl(base_impl &&) noexcept = default;
    base_impl &operator=(base_impl &&) noexcept = default;

    [[nodiscard]] eval_result eval(condition_cache &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> & /*unused*/,
        ddwaf::timer &deadline) const override
    {

        using func_traits = decltype(make_eval_traits(&Self::eval_impl));
        typename func_traits::tuple_type args;

        static_assert(func_traits::nargs == Self::param_names.size());

        if (!resolve_arguments(
                store, objects_excluded, args, std::make_index_sequence<func_traits::nargs>{})) {
            return {};
        }

        return std::apply(
            [&](auto &&...args) {
                return static_cast<const Self *>(this)->eval_impl(
                    std::forward<decltype(args)>(args)..., cache, objects_excluded, deadline);
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
        using func_traits = decltype(make_eval_traits(&Self::eval_impl));
        static_assert(param_names.size() <= func_traits::nargs);

        return std::array<parameter_specification, sizeof...(Is)>{{
            {
                param_names[Is],
                argument_retriever<typename func_traits::template arg_type<Is>>::is_variadic,
                argument_retriever<typename func_traits::template arg_type<Is>>::is_optional,
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
    bool resolve_arguments(const object_store &store,
        const exclusion::object_set_ref &objects_excluded, Args &args,
        std::index_sequence<I, Is...> /*unused*/) const
    {
        using TupleElement = std::tuple_element_t<I, Args>;
        auto arg = resolve_argument<I>(store, objects_excluded);
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
            return resolve_arguments(store, objects_excluded, args, std::index_sequence<Is...>{});
        } else {
            return true;
        }
    }

    template <size_t I>
    auto resolve_argument(
        const object_store &store, const exclusion::object_set_ref &objects_excluded) const
    {
        using func_traits = decltype(make_eval_traits(&Self::eval_impl));
        using target_type = typename func_traits::template arg_type<I>;

        using retriever = argument_retriever<target_type>;
        if constexpr (retriever::is_variadic) {
            if (arguments_.size() <= I) {
                return target_type{};
            }
            return retriever::retrieve(store, objects_excluded, arguments_[I].targets);
        } else {
            if (arguments_.size() <= I) {
                return std::optional<target_type>{};
            }

            const auto &arg = arguments_[I];
            if (arg.targets.empty()) {
                return std::optional<target_type>{};
            }
            return retriever::retrieve(store, objects_excluded, arg.targets.at(0));
        }
    }

    std::vector<parameter_definition> arguments_;
    const object_limits limits_;
};

} // namespace ddwaf
