// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include "condition/scalar_condition.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "radixlib.h"
#include "ruleset.hpp"

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

#define LSTRARG(value) value, sizeof(value) - 1

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

// Convenience structure to build rulesets
struct ruleset_builder {
    explicit ruleset_builder(ddwaf_object_free_fn free_fn = ddwaf_object_free)
        : free_fn(free_fn == nullptr ? ddwaf_object_free_not : free_fn),
          preprocessors(std::make_shared<typename decltype(preprocessors)::element_type>()),
          postprocessors(std::make_shared<typename decltype(postprocessors)::element_type>()),
          rule_filters(std::make_shared<typename decltype(rule_filters)::element_type>()),
          input_filters(std::make_shared<typename decltype(input_filters)::element_type>()),
          base_rules(std::make_shared<typename decltype(base_rules)::element_type>()),
          user_rules(std::make_shared<typename decltype(user_rules)::element_type>()),
          rule_matchers(std::make_shared<typename decltype(rule_matchers)::element_type>()),
          exclusion_matchers(
              std::make_shared<typename decltype(exclusion_matchers)::element_type>()),
          scanners(std::make_shared<typename decltype(scanners)::element_type>()),
          actions(std::make_shared<typename decltype(actions)::element_type>())
    {
        // Prealloc to ensure pointers to rules are valid
        // TODO this is hacky, fix it
        base_rules->reserve(32);
        user_rules->reserve(32);
    }

    core_rule *insert_base_rule(core_rule &&rule)
    {
        return &base_rules->emplace_back(std::move(rule));
    }

    core_rule *insert_user_rule(core_rule &&rule)
    {
        return &user_rules->emplace_back(std::move(rule));
    }

    template <typename T> void insert_filter(T &&filter)
    {
        if constexpr (std::is_same_v<T, exclusion::rule_filter>) {
            rule_filters->emplace_back(std::forward<T>(filter));
        } else {
            input_filters->emplace_back(std::forward<T>(filter));
        }
    }

    void insert_preprocessor(std::unique_ptr<base_processor> &&proc)
    {
        preprocessors->emplace_back(std::move(proc));
    }

    void insert_postprocessor(std::unique_ptr<base_processor> &&proc)
    {
        postprocessors->emplace_back(std::move(proc));
    }

    [[nodiscard]] std::shared_ptr<ddwaf::ruleset> build() const
    {
        auto ruleset = std::make_shared<ddwaf::ruleset>();
        ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

        ruleset->free_fn = free_fn;
        ruleset->insert_preprocessors(preprocessors);
        ruleset->insert_rules(base_rules, user_rules);
        ruleset->insert_filters(rule_filters);
        ruleset->insert_filters(input_filters);
        ruleset->insert_postprocessors(postprocessors);

        ruleset->rule_matchers = rule_matchers;
        ruleset->exclusion_matchers = exclusion_matchers;
        ruleset->scanners = scanners;
        ruleset->actions = actions;

        return ruleset;
    }

    ddwaf_object_free_fn free_fn;
    std::shared_ptr<std::vector<std::unique_ptr<base_processor>>> preprocessors;
    std::shared_ptr<std::vector<std::unique_ptr<base_processor>>> postprocessors;

    std::shared_ptr<std::vector<exclusion::rule_filter>> rule_filters;
    std::shared_ptr<std::vector<exclusion::input_filter>> input_filters;

    std::shared_ptr<std::vector<core_rule>> base_rules;
    std::shared_ptr<std::vector<core_rule>> user_rules;

    std::shared_ptr<matcher_mapper> rule_matchers;
    std::shared_ptr<matcher_mapper> exclusion_matchers;

    std::shared_ptr<std::vector<scanner>> scanners;
    std::shared_ptr<action_mapper> actions;
};

} // namespace ddwaf::test
