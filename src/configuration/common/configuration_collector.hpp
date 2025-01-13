// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include "configuration/common/configuration.hpp"

namespace ddwaf {

class configuration_collector {
public:
    configuration_collector(configuration_change_spec &change, configuration_spec &config)
        : change_(change), config_(config){};
    configuration_collector(const configuration_collector &) = delete;
    configuration_collector &operator=(const configuration_collector &) = delete;
    configuration_collector(configuration_collector &&) = delete;
    configuration_collector &operator=(configuration_collector &&) = delete;
    ~configuration_collector() = default;

    [[nodiscard]] bool contains_rule(const std::string &id) const
    {
        return config_.base_rules.contains(id) || config_.user_rules.contains(id);
    }

    [[nodiscard]] bool contains_filter(const std::string &id) const
    {
        return config_.rule_filters.contains(id) || config_.input_filters.contains(id);
    }

    [[nodiscard]] bool contains_processor(const std::string &id) const
    {
        return config_.processors.contains(id);
    }

    [[nodiscard]] bool contains_scanner(const std::string &id) const
    {
        return config_.scanners.contains(id);
    }

    [[nodiscard]] bool contains_action(const std::string &id) const
    {
        return config_.actions.contains(id);
    }

    void emplace_rule(std::string id, rule_spec spec)
    {
        if (spec.source == core_rule::source_type::base) {
            change_.content = change_.content | change_set::rules;

            change_.base_rules.emplace(id);
            config_.base_rules.emplace(std::move(id), std::move(spec));
        } else {
            change_.content = change_.content | change_set::custom_rules;

            change_.base_rules.emplace(id);
            config_.base_rules.emplace(std::move(id), std::move(spec));
        }
    }

    void emplace_override(std::string id, override_spec spec)
    {
        change_.content = change_.content | change_set::overrides;

        if (spec.type == reference_type::id) {
            change_.overrides_by_id.emplace(id);
            config_.overrides_by_id.emplace(std::move(id), std::move(spec));
        } else if (spec.type == reference_type::tags) {
            change_.overrides_by_tags.emplace(id);
            config_.overrides_by_tags.emplace(std::move(id), std::move(spec));
        }
    }

    void emplace_filter(std::string id, rule_filter_spec spec)
    {
        change_.content = change_.content | change_set::filters;

        change_.rule_filters.emplace(id);
        config_.rule_filters.emplace(std::move(id), std::move(spec));
    }

    void emplace_filter(std::string id, input_filter_spec spec)
    {
        change_.content = change_.content | change_set::filters;

        change_.input_filters.emplace(id);
        config_.input_filters.emplace(std::move(id), std::move(spec));
    }

    void emplace_processor(std::string id, processor_spec spec)
    {
        change_.content = change_.content | change_set::processors;

        change_.processors.emplace(id);
        config_.processors.emplace(std::move(id), std::move(spec));
    }

    void emplace_scanner(std::shared_ptr<scanner> scanner)
    {
        change_.content = change_.content | change_set::scanners;

        change_.scanners.emplace(scanner->get_id());
        config_.scanners.emplace(std::move(scanner));
    }

    void emplace_action(std::string id, action_spec spec)
    {
        change_.content = change_.content | change_set::actions;

        change_.actions.emplace(id);
        config_.actions.emplace(std::move(id), std::move(spec));
    }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void emplace_rule_data(std::string data_id, std::string id, data_type type,
        std::vector<data_spec::value_type> values)
    {
        change_.content = change_.content | change_set::rule_data;

        auto it = config_.rule_data.find(data_id);
        if (it == config_.rule_data.end()) {
            auto &spec = config_.rule_data[data_id];
            spec.type = type;
            spec.values.emplace(id, std::move(values));
        } else {
            // TODO fail if type differs
            it->second.values.emplace(id, std::move(values));
        }
        change_.rule_data.emplace_back(std::move(data_id), std::move(id));
    }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void emplace_exclusion_data(std::string data_id, std::string id, data_type type,
        std::vector<data_spec::value_type> values)
    {
        change_.content = change_.content | change_set::exclusion_data;

        auto it = config_.exclusion_data.find(data_id);
        if (it == config_.exclusion_data.end()) {
            auto &spec = config_.exclusion_data[data_id];
            spec.type = type;
            spec.values.emplace(id, std::move(values));
        } else {
            // TODO fail if type differs
            it->second.values.emplace(id, std::move(values));
        }
        change_.exclusion_data.emplace_back(std::move(data_id), std::move(id));
    }

protected:
    configuration_change_spec &change_;
    configuration_spec &config_;
};

} // namespace ddwaf
