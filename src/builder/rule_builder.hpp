// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "configuration/common/configuration.hpp"
#include "indexer.hpp"
#include "rule.hpp"

namespace ddwaf {

class rule_builder {
public:
    explicit rule_builder(std::string id, rule_spec spec)
        : id_(std::move(id)), spec_(std::move(spec))
    {}

    std::string_view get_id() const { return id_; }
    const std::unordered_map<std::string, std::string> &get_tags() const { return spec_.tags; }
    [[nodiscard]] bool is_enabled() const { return spec_.enabled; }

    bool apply_override(const override_spec &ovrd)
    {
        if (ovrd.enabled.has_value()) {
            spec_.enabled = *ovrd.enabled;
        }

        if (ovrd.actions.has_value()) {
            spec_.actions = *ovrd.actions;
        }

        for (const auto &[key, value] : ovrd.tags) {
            if (!spec_.tags.contains(key)) {
                ancillary_tags_[key] = value;
            }
        }

        return true;
    }

    std::shared_ptr<core_rule> build(const action_mapper &mapper)
    {
        core_rule::verdict_type verdict = core_rule::verdict_type::monitor;
        for (const auto &action : spec_.actions) {
            auto it = mapper.find(action);
            if (it == mapper.end()) {
                continue;
            }

            auto action_mode = it->second.type;
            if (is_blocking_action(action_mode)) {
                verdict = core_rule::verdict_type::block;
                break;
            }
        }

        ancillary_tags_.merge(spec_.tags);

        return std::make_shared<core_rule>(std::move(id_), std::move(spec_.name),
            std::move(ancillary_tags_), std::move(spec_.expr), std::move(spec_.actions),
            spec_.enabled, spec_.source, verdict);
    }

protected:
    std::string id_;
    rule_spec spec_;
    std::unordered_map<std::string, std::string> ancillary_tags_;
};

} // namespace ddwaf
