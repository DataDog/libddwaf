// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include "configuration/common/configuration.hpp"
#include "indexer.hpp"
#include "rule.hpp"
#include "ruleset.hpp"

namespace ddwaf {

class ruleset_builder {
public:
    ruleset_builder() = default;
    ~ruleset_builder() = default;
    ruleset_builder(ruleset_builder &&) = default;
    ruleset_builder(const ruleset_builder &) = delete;
    ruleset_builder &operator=(ruleset_builder &&) = delete;
    ruleset_builder &operator=(const ruleset_builder &) = delete;

    std::shared_ptr<ruleset> build(
        const configuration_spec &global_config, change_set current_changes);

protected:
    // These contain the specification of each main component obtained directly
    // from the parser. These are only modified on update, if the relevant key
    // is present and valid, otherwise they aren't be updated.
    // Note that in the case of dynamic_matchers, overrides and exclusions
    // we allow an empty key as a way to revert or remove the contents of the
    // relevant feature.

    // Base Rules
    std::shared_ptr<const std::vector<core_rule>> final_base_rules_;
    std::shared_ptr<const std::vector<core_rule>> final_user_rules_;
    indexer<const core_rule> rule_index_;

    // Filters
    std::shared_ptr<const std::vector<rule_filter>> rule_filters_;
    std::shared_ptr<const std::vector<input_filter>> input_filters_;

    // Processors
    std::shared_ptr<const std::vector<std::unique_ptr<base_processor>>> preprocessors_;
    std::shared_ptr<const std::vector<std::unique_ptr<base_processor>>> postprocessors_;

    // Matchers
    std::shared_ptr<const matcher_mapper> rule_matchers_;
    std::shared_ptr<const matcher_mapper> exclusion_matchers_;

    // Scanners
    std::shared_ptr<const std::vector<scanner>> scanners_;
    indexer<const scanner> scanner_index_;

    // Actions
    std::shared_ptr<const action_mapper> actions_;

    // Obfuscator
    std::shared_ptr<match_obfuscator> obfuscator_;
};

} // namespace ddwaf
