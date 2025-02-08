// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "configuration/common/common.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/matcher_parser.hpp"
#include "configuration/scanner_parser.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ruleset_info.hpp"
#include "scanner.hpp"
#include "semver.hpp"
#include "version.hpp"

namespace ddwaf {

namespace {

std::unique_ptr<matcher::base> parse_scanner_matcher(const raw_configuration::map &root)
{
    auto matcher_name = at<std::string_view>(root, "operator");
    auto matcher_params = at<raw_configuration::map>(root, "parameters");

    auto [rule_data_id, matcher] = parse_any_matcher(matcher_name, matcher_params);
    if (!rule_data_id.empty()) {
        throw ddwaf::parsing_error("dynamic data on scanner condition");
    }

    return std::move(matcher);
}

} // namespace

void parse_scanners(const raw_configuration::vector &scanner_array, configuration_collector &cfg,
    ruleset_info::base_section_info &info)
{
    for (unsigned i = 0; i < scanner_array.size(); i++) {
        const auto &node_param = scanner_array[i];
        auto node = static_cast<raw_configuration::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (cfg.contains_scanner(id)) {
                DDWAF_WARN("Duplicate scanner: {}", id);
                info.add_failed(id, "duplicate scanner");
                continue;
            }

            // Check version compatibility and fail without diagnostic
            auto min_version{at<semantic_version>(node, "min_version", semantic_version::min())};
            auto max_version{at<semantic_version>(node, "max_version", semantic_version::max())};
            if (min_version > current_version || max_version < current_version) {
                DDWAF_DEBUG("Skipping scanner '{}': version required between [{}, {}], current {}",
                    id, min_version, max_version, current_version);
                info.add_skipped(id);
                continue;
            }

            std::unordered_map<std::string, std::string> tags;
            for (auto &[key, value] : at<raw_configuration::map>(node, "tags")) {
                try {
                    tags.emplace(key, std::string(value));
                } catch (const bad_cast &e) {
                    throw invalid_type(std::string(key), e);
                }
            }

            std::unique_ptr<matcher::base> key_matcher{};
            std::unique_ptr<matcher::base> value_matcher{};

            auto it = node.find("key");
            if (it != node.end()) {
                auto matcher_node = raw_configuration::map(it->second);
                key_matcher = parse_scanner_matcher(matcher_node);
            }

            it = node.find("value");
            if (it != node.end()) {
                auto matcher_node = raw_configuration::map(it->second);
                value_matcher = parse_scanner_matcher(matcher_node);
            }

            if (!key_matcher && !value_matcher) {
                DDWAF_WARN("Scanner {} has no key or value matcher", id);
                info.add_failed(id, "scanner has no key or value matcher");
                continue;
            }

            DDWAF_DEBUG("Parsed scanner {}", id);
            info.add_loaded(id);
            scanner scnr{id, std::move(tags), std::move(key_matcher), std::move(value_matcher)};
            cfg.emplace_scanner(std::move(id), std::move(scnr));
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse scanner '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }
}

} // namespace ddwaf
