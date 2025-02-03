// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <unordered_map>

#include "configuration/common/configuration.hpp"
#include "indexer.hpp"
#include "rule.hpp"
#include "ruleset.hpp"

namespace ddwaf {

class ruleset_builder {
public:
    explicit ruleset_builder(object_limits limits = {},
        ddwaf_object_free_fn free_fn = ddwaf_object_free,
        std::shared_ptr<ddwaf::obfuscator> event_obfuscator = std::make_shared<ddwaf::obfuscator>())
        : limits_(limits), free_fn_(free_fn), event_obfuscator_(std::move(event_obfuscator))
    {}

    ~ruleset_builder() = default;
    ruleset_builder(ruleset_builder &&) = default;
    ruleset_builder(const ruleset_builder &) = delete;
    ruleset_builder &operator=(ruleset_builder &&) = delete;
    ruleset_builder &operator=(const ruleset_builder &) = delete;

    std::shared_ptr<ruleset> build(
        const configuration_spec &global_config, change_set current_changes);

protected:
    // These members are obtained through ddwaf_config and are persistent across
    // all updates.
    object_limits limits_;
    ddwaf_object_free_fn free_fn_;
    std::shared_ptr<ddwaf::obfuscator> event_obfuscator_;

    // These contain the specification of each main component obtained directly
    // from the parser. These are only modified on update, if the relevant key
    // is present and valid, otherwise they aren't be updated.
    // Note that in the case of dynamic_matchers, overrides and exclusions
    // we allow an empty key as a way to revert or remove the contents of the
    // relevant feature.

    // Rules
    indexer<core_rule> final_base_rules_;
    indexer<core_rule> final_user_rules_;

    // Filters
    std::shared_ptr<std::vector<exclusion::rule_filter>> rule_filters_;
    std::shared_ptr<std::vector<exclusion::input_filter>> input_filters_;

    // Processors
    std::shared_ptr<std::vector<std::unique_ptr<base_processor>>> preprocessors_;
    std::shared_ptr<std::vector<std::unique_ptr<base_processor>>> postprocessors_;

    // Matchers
    std::unordered_map<std::string, std::shared_ptr<matcher::base>> rule_matchers_;
    std::unordered_map<std::string, std::shared_ptr<matcher::base>> exclusion_matchers_;

    // Actions
    std::shared_ptr<const action_mapper> actions_;
};

} // namespace ddwaf
