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

#include "exception.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/specification.hpp"

namespace ddwaf::parser::v2 {

namespace {

std::pair<override_spec, reference_type> parse_override(const parameter::map &node)
{
    // Note that ID is a duplicate field and will be deprecated at some point
    override_spec current;

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

    reference_type type = reference_type::none;

    auto rules_target_array = at<parameter::vector>(node, "rules_target", {});
    if (!rules_target_array.empty()) {
        current.targets.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            auto target_spec = parse_reference(static_cast<parameter::map>(target));
            if (type == reference_type::none) {
                type = target_spec.type;
            } else if (type != target_spec.type) {
                throw ddwaf::parsing_error("rule override targets rules and tags");
            }

            current.targets.emplace_back(std::move(target_spec));
        }
    } else {
        // Since the rules_target array is empty, the ID is mandatory
        current.targets.emplace_back(reference_type::id, at<std::string>(node, "id"),
            std::unordered_map<std::string, std::string>{});
        type = reference_type::id;
    }

    if (!current.actions.has_value() && !current.enabled.has_value() && current.tags.empty()) {
        throw ddwaf::parsing_error("rule override without side-effects");
    }

    return {current, type};
}

} // namespace

override_spec_container parse_overrides(parameter::vector &override_array, base_section_info &info)
{
    override_spec_container overrides;

    for (unsigned i = 0; i < override_array.size(); ++i) {
        auto id = index_to_id(i);
        const auto &node_param = override_array[i];
        auto node = static_cast<parameter::map>(node_param);
        try {
            auto [spec, type] = parse_override(node);
            if (type == reference_type::id) {
                overrides.by_ids.emplace_back(std::move(spec));
            } else if (type == reference_type::tags) {
                overrides.by_tags.emplace_back(std::move(spec));
            } else {
                // This code is likely unreachable
                DDWAF_WARN("Rule override with no targets");
                info.add_failed(id, "rule override with no targets");
                continue;
            }
            DDWAF_DEBUG("Parsed override {}", id);
            info.add_loaded(id);
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse rule override: {}", e.what());
            info.add_failed(id, e.what());
        }
    }

    return overrides;
}

} // namespace ddwaf::parser::v2
