// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include "condition/scalar_condition.hpp"
#include "context_allocator.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "ruleset.hpp"
#include "utils.hpp"

// 1s and 1us
#define LONG_TIME 1000000
#define SHORT_TIME 1

#define DDWAF_OBJECT_INVALID                                                                       \
    {                                                                                              \
        NULL, 0, {NULL}, 0, DDWAF_OBJ_INVALID                                                      \
    }
#define DDWAF_OBJECT_MAP                                                                           \
    {                                                                                              \
        NULL, 0, {NULL}, 0, DDWAF_OBJ_MAP                                                          \
    }
#define DDWAF_OBJECT_ARRAY                                                                         \
    {                                                                                              \
        NULL, 0, {NULL}, 0, DDWAF_OBJ_ARRAY                                                        \
    }
#define DDWAF_OBJECT_SIGNED_FORCE(value)                                                           \
    {                                                                                              \
        NULL, 0, {(const char *)value}, 0, DDWAF_OBJ_SIGNED                                        \
    }
#define DDWAF_OBJECT_UNSIGNED_FORCE(value)                                                         \
    {                                                                                              \
        NULL, 0, {(const char *)value}, 0, DDWAF_OBJ_UNSIGNED                                      \
    }
#define DDWAF_OBJECT_STRING_PTR(string, length)                                                    \
    {                                                                                              \
        NULL, 0, {string}, length, DDWAF_OBJ_STRING                                                \
    }

namespace ddwaf::test {

class expression_builder {
public:
    explicit expression_builder(std::size_t num_conditions) { conditions_.reserve(num_conditions); }

    void start_condition() { arguments_.clear(); }

    template <typename T, bool Expected = true, typename... Args>
    void end_condition(Args... args)
        requires std::is_base_of_v<matcher::base, T>
    {
        if constexpr (Expected) {
            conditions_.emplace_back(
                std::make_unique<scalar_condition>(std::make_unique<T>(std::forward<Args>(args)...),
                    std::string{}, std::move(arguments_)));
        } else {
            conditions_.emplace_back(std::make_unique<scalar_negated_condition>(
                std::make_unique<T>(std::forward<Args>(args)...), std::string{},
                std::move(arguments_)));
        }
    }

    template <typename T, bool Expected = true>
    void end_condition_with_data(std::string data_id)
        requires std::is_base_of_v<matcher::base, T>
    {
        if constexpr (Expected) {
            conditions_.emplace_back(std::make_unique<scalar_condition>(
                std::unique_ptr<matcher::base>{}, std::move(data_id), std::move(arguments_)));
        } else {
            conditions_.emplace_back(std::make_unique<scalar_negated_condition>(
                std::unique_ptr<matcher::base>{}, std::move(data_id), std::move(arguments_)));
        }
    }

    template <typename T>
    void end_condition()
        requires std::is_base_of_v<base_condition, T>
    {
        conditions_.emplace_back(std::make_unique<T>(std::move(arguments_)));
    }

    void add_argument() { arguments_.emplace_back(); }

    void add_target(const std::string &name, std::vector<std::string> key_path = {},
        std::vector<transformer_id> transformers = {}, data_source source = data_source::values)
    {
        auto &argument = arguments_.back();
        argument.targets.emplace_back(condition_target{
            name, get_target_index(name), std::move(key_path), std::move(transformers), source});
    }

    std::shared_ptr<expression> build()
    {
        return std::make_shared<expression>(std::move(conditions_));
    }

protected:
    std::vector<condition_parameter> arguments_{};
    std::vector<std::unique_ptr<base_condition>> conditions_{};
};

inline std::shared_ptr<ddwaf::ruleset> get_default_ruleset()
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();
    ruleset->actions = std::make_shared<ddwaf::action_mapper>();
    return ruleset;
}

} // namespace ddwaf::test
