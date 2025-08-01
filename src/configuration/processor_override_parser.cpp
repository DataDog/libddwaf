// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <exception>
#include <string>
#include <utility>
#include <vector>

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/common/reference_parser.hpp"
#include "configuration/processor_override_parser.hpp"
#include "log.hpp"
#include "ruleset_info.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {

processor_override_spec parse_override(const raw_configuration::map &node)
{
    // Note that ID is a duplicate field and will be deprecated at some point
    processor_override_spec current;

    auto target_array = at<raw_configuration::vector>(node, "target");
    if (target_array.empty()) {
        throw ddwaf::parsing_error("processor override without targets");
    }

    current.targets.reserve(target_array.size());
    for (const auto &target : target_array) {
        auto target_spec = parse_reference(static_cast<raw_configuration::map>(target));
        if (target_spec.type == reference_type::tags) {
            throw ddwaf::parsing_error("processor override with target by tags not supported");
        }
        current.targets.emplace_back(std::move(target_spec));
    }

    auto scanners_target_array = at<raw_configuration::vector>(node, "scanners");
    current.scanners.reserve(scanners_target_array.size());
    for (const auto &target : scanners_target_array) {
        auto target_spec = parse_reference(static_cast<raw_configuration::map>(target));
        current.scanners.emplace_back(std::move(target_spec));
    }

    return current;
}

} // namespace

void parse_processor_overrides(const raw_configuration::vector &override_array,
    configuration_collector &cfg, ruleset_info::section_info &info)
{
    for (unsigned i = 0; i < override_array.size(); ++i) {
        const auto &node_param = override_array[i];
        auto node = static_cast<raw_configuration::map>(node_param);
        try {
            auto spec = parse_override(node);
            DDWAF_DEBUG("Parsed processor override index:{}", i);
            info.add_loaded(i);
            // We use a UUID since we want to have a unique identifier across
            // all configurations
            cfg.emplace_processor_override(uuidv4_generate_pseudo(), std::move(spec));
        } catch (const parsing_exception &e) {
            DDWAF_WARN("Failed to parse processor override: {}", e.what());
            info.add_failed(i, e.severity(), e.what());
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse processor override: {}", e.what());
            info.add_failed(i, parser_error_severity::error, e.what());
        }
    }
}

} // namespace ddwaf
