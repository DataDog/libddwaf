// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <exception>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/reference_parser.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {

override_spec parse_override(const parameter::map &node)
{
    // Note that ID is a duplicate field and will be deprecated at some point
    override_spec current;
    current.type = reference_type::none;

    auto it = node.find("enabled");
    if (it != node.end()) {
        current.enabled = static_cast<bool>(it->second);
    }

    it = node.find("on_match");
    if (it != node.end()) {
        auto actions = static_cast<std::vector<std::string>>(it->second);
        current.actions = std::move(actions);
    }

    it = node.find("tags");
    if (it != node.end()) {
        auto tags = static_cast<std::unordered_map<std::string, std::string>>(it->second);
        current.tags = std::move(tags);
    }

    auto rules_target_array = at<parameter::vector>(node, "rules_target", {});
    if (!rules_target_array.empty()) {
        current.targets.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            auto target_spec = parse_reference(static_cast<parameter::map>(target));
            if (current.type == reference_type::none) {
                current.type = target_spec.type;
            } else if (current.type != target_spec.type) {
                throw ddwaf::parsing_error("rule override targets rules and tags");
            }

            current.targets.emplace_back(std::move(target_spec));
        }
    } else {
        // Since the rules_target array is empty, the ID is mandatory
        reference_spec ref_spec{reference_type::id, at<std::string>(node, "id"), {}};
        current.targets.emplace_back(std::move(ref_spec));
        current.type = reference_type::id;
    }

    if (!current.actions.has_value() && !current.enabled.has_value() && current.tags.empty()) {
        throw ddwaf::parsing_error("rule override without side-effects");
    }

    return current;
}

} // namespace

void parse_overrides(const parameter::vector &override_array, configuration_collector &cfg,
    ruleset_info::base_section_info &info)
{
    for (unsigned i = 0; i < override_array.size(); ++i) {
        auto id = index_to_id(i);
        const auto &node_param = override_array[i];
        auto node = static_cast<parameter::map>(node_param);
        try {
            auto spec = parse_override(node);
            if (spec.type == reference_type::none) {
                // This code is likely unreachable
                DDWAF_WARN("Rule override with no targets");
                info.add_failed(id, "rule override with no targets");
                continue;
            }

            DDWAF_DEBUG("Parsed override {}", id);
            info.add_loaded(id);
            // We use a UUID since we want to have a unique identifier across
            // all configurations
            cfg.emplace_override(uuidv4_generate_pseudo(), std::move(spec));
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse rule override: {}", e.what());
            info.add_failed(id, e.what());
        }
    }
}

} // namespace ddwaf