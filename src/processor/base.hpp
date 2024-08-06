// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "argument_retriever.hpp"
#include "exception.hpp"
#include "expression.hpp"
#include "object_store.hpp"
#include "utils.hpp"

namespace ddwaf {

struct processor_target {
    target_index index;
    std::string name;
    std::vector<std::string> key_path;
};

struct processor_parameter {
    std::vector<processor_target> targets;
};

struct processor_mapping {
    std::vector<processor_parameter> inputs;
    processor_target output;
};

struct processor_cache {
    expression::cache_type expr_cache;
    std::unordered_set<target_index> generated;

    std::vector<std::size_t> optionals_evaluated;
};

template <typename Class, typename... Args>
function_traits<Class::param_names.size(), Class, Args...> make_eval_traits(
    std::pair<ddwaf_object, object_store::attribute> (Class::*)(Args...) const);

template <typename T, typename... Ts> constexpr std::size_t count_optionals()
{
    if constexpr (sizeof...(Ts) == 0) {
        return static_cast<std::size_t>(is_optional_argument<T>::value);
    } else {
        return is_optional_argument<T>::value + count_optionals<Ts...>();
    }
}

template <typename T> struct tuple_optionals_trait;

template <typename... Ts> struct tuple_optionals_trait<std::tuple<Ts...>> {
    static constexpr std::size_t count = count_optionals<Ts...>();
    static constexpr bool value = count > 0;
};

template <typename T>
concept is_tuple_with_optional = tuple_optionals_trait<T>::value;

class base_processor {
public:
    base_processor() = default;
    base_processor(const base_processor &) = delete;
    base_processor &operator=(const base_processor &) = delete;

    base_processor(base_processor &&rhs) noexcept = default;
    base_processor &operator=(base_processor &&rhs) noexcept = default;
    virtual ~base_processor() = default;

    virtual void eval(object_store &store, optional_ref<ddwaf_object> &derived,
        processor_cache &cache, ddwaf::timer &deadline) const = 0;

    virtual void get_addresses(std::unordered_map<target_index, std::string> &addresses) const = 0;

    [[nodiscard]] virtual const std::string &get_id() const = 0;
};

template <typename Self> class structured_processor : public base_processor {
public:
    structured_processor(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : id_(std::move(id)), expr_(std::move(expr)), mappings_(std::move(mappings)),
          evaluate_(evaluate), output_(output)
    {}

    structured_processor(const structured_processor &) = delete;
    structured_processor &operator=(const structured_processor &) = delete;

    structured_processor(structured_processor &&rhs) noexcept = default;
    structured_processor &operator=(structured_processor &&rhs) noexcept = default;
    ~structured_processor() override = default;

    void eval(object_store &store, optional_ref<ddwaf_object> &derived, processor_cache &cache,
        ddwaf::timer &deadline) const override
    {
        // No result structure, but this processor only produces derived objects
        // so it makes no sense to evaluate.
        if (!derived.has_value() && !evaluate_ && output_) {
            return;
        }

        DDWAF_DEBUG("Evaluating processor '{}'", id_);

        if (!expr_->eval(cache.expr_cache, store, {}, {}, deadline).outcome) {
            return;
        }

        using func_traits = decltype(make_eval_traits(&Self::eval_impl));
        using tuple_type = typename func_traits::tuple_type;
        static_assert(func_traits::nargs == Self::param_names.size());

        if constexpr (is_tuple_with_optional<tuple_type>) {
            // If the processor has optional parameters, initialise the cache to
            // ensure that we can keep track of the number of optional arguments
            // seen and reevaluate as necessary.
            if (cache.optionals_evaluated.size() < mappings_.size()) {
                cache.optionals_evaluated.resize(mappings_.size(), 0);
            }
        }

        for (std::size_t i = 0; i < mappings_.size(); ++i) {
            const auto &mapping = mappings_[i];
            if (deadline.expired()) {
                throw ddwaf::timeout_exception();
            }

            if (store.has_target(mapping.output.index) ||
                cache.generated.find(mapping.output.index) != cache.generated.end()) {
                if constexpr (is_tuple_with_optional<tuple_type>) {
                    // When the processor has optional arguments, these should still be
                    // resolved as there could be new ones available
                    if (cache.optionals_evaluated[i] == tuple_optionals_trait<tuple_type>::count) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            tuple_type args;
            auto arg_count = resolve_arguments(
                mapping, store, args, std::make_index_sequence<func_traits::nargs>{});
            if constexpr (is_tuple_with_optional<tuple_type>) {
                // If there are no new optional arguments, or no arguments at all, skip
                if (arg_count.all == 0 || arg_count.optional == cache.optionals_evaluated[i]) {
                    continue;
                }
            } else {
                if (arg_count.all == 0) {
                    continue;
                }
            }

            auto [object, attr] = std::apply(
                [&](auto &&...args) {
                    return static_cast<const Self *>(this)->eval_impl(
                        std::forward<decltype(args)>(args)..., deadline);
                },
                std::move(args));
            if (attr != object_store::attribute::ephemeral) {
                // Whatever the outcome, we don't want to try and generate it again
                cache.generated.emplace(mapping.output.index);

                // We update the number of optionals evaluated so that we can
                // eventually determine whether the processor should be called
                // again or not. The number of optionals found should increase
                // on every call, hence why we simply replace the value.
                if constexpr (is_tuple_with_optional<tuple_type>) {
                    cache.optionals_evaluated[i] = arg_count.optional;
                }
            }

            if (object.type == DDWAF_OBJ_INVALID) {
                continue;
            }

            if (evaluate_) {
                store.insert(mapping.output.index, mapping.output.name, object, attr);
            }

            if (output_ && derived.has_value()) {
                ddwaf_object &output = derived.value();
                if (evaluate_) {
                    auto copy = ddwaf::object::clone(&object);
                    ddwaf_object_map_add(&output, mapping.output.name.c_str(), &copy);
                } else {
                    ddwaf_object_map_add(&output, mapping.output.name.c_str(), &object);
                }
            }
        }
    }
    [[nodiscard]] const std::string &get_id() const override { return id_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const override
    {
        expr_->get_addresses(addresses);
        for (const auto &mapping : mappings_) {
            for (const auto &input : mapping.inputs) {
                for (const auto &target : input.targets) {
                    addresses.emplace(target.index, target.name);
                }
            }
        }
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

protected:
    struct resolved_count {
        std::size_t all{0};
        std::size_t optional{0};
    };

    template <size_t I, size_t... Is, typename Args>
    resolved_count resolve_arguments(const processor_mapping &mapping, const object_store &store,
        Args &args, std::index_sequence<I, Is...> /*unused*/, resolved_count count = {}) const
    {
        using TupleElement = std::tuple_element_t<I, Args>;
        auto arg = resolve_argument<I>(mapping, store);
        if constexpr (is_unary_argument<TupleElement>::value) {
            if (!arg.has_value()) {
                return {};
            }

            ++count.all;
            std::get<I>(args) = std::move(arg.value());
        } else if constexpr (is_variadic_argument<TupleElement>::value) {
            if (arg.empty()) {
                return {};
            }

            ++count.all;
            std::get<I>(args) = std::move(arg);
        } else {
            // If an optional value is not available, the resolution of said
            // argument doesn't increase the number of arguments resolsved.
            // This ensures that when all arguments in a method are optional,
            // we can prevent calling it if none of the arguments are available.
            count.all += static_cast<std::size_t>(arg.has_value());
            count.optional += static_cast<std::size_t>(arg.has_value());
            std::get<I>(args) = std::move(arg);
        }

        if constexpr (sizeof...(Is) > 0) {
            return resolve_arguments(mapping, store, args, std::index_sequence<Is...>{}, count);
        } else {
            return count;
        }
    }

    template <size_t I>
    auto resolve_argument(const processor_mapping &mapping, const object_store &store) const
    {
        using func_traits = decltype(make_eval_traits(&Self::eval_impl));
        using target_type = typename func_traits::template arg_type<I>;

        using retriever = argument_retriever<target_type>;
        if constexpr (retriever::is_variadic) {
            if (mapping.inputs.size() <= I) {
                return target_type{};
            }
            return retriever::retrieve(store, {}, mapping.inputs[I].targets);
        } else if constexpr (retriever::is_optional) {
            if (mapping.inputs.size() <= I) {
                return target_type{};
            }

            const auto &arg = mapping.inputs[I];
            if (arg.targets.empty()) {
                return target_type{};
            }
            return retriever::retrieve(store, {}, arg.targets.at(0));
        } else {
            if (mapping.inputs.size() <= I) {
                return std::optional<target_type>{};
            }

            const auto &arg = mapping.inputs[I];
            if (arg.targets.empty()) {
                return std::optional<target_type>{};
            }
            return retriever::retrieve(store, {}, arg.targets.at(0));
        }
    }
    std::string id_;
    std::shared_ptr<expression> expr_;
    std::vector<processor_mapping> mappings_;
    bool evaluate_{false};
    bool output_{true};
};

} // namespace ddwaf
