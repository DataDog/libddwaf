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
#include "configuration/common/expression_parser.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/common/reference_parser.hpp"
#include "configuration/processor_parser.hpp"
#include "log.hpp"
#include "processor/base.hpp"
#include "processor/extract_schema.hpp"
#include "processor/fingerprint.hpp"
#include "processor/jwt_decode.hpp"
#include "processor/uri_parse.hpp"
#include "ruleset_info.hpp"
#include "semver.hpp"
#include "target_address.hpp"
#include "version.hpp"

namespace ddwaf {

namespace {
std::vector<processor_mapping> parse_processor_mappings(
    const raw_configuration::vector &root, const auto &param_names)
{
    if (root.empty()) {
        throw ddwaf::parsing_error("empty mappings");
    }

    std::vector<processor_mapping> mappings;
    for (const auto &node : root) {
        auto mapping = static_cast<raw_configuration::map>(node);

        std::vector<processor_parameter> parameters;
        for (const auto &param : param_names) {
            // TODO support n:1 mappings and key paths
            auto inputs = at<raw_configuration::vector>(mapping, param);
            if (inputs.empty()) {
                throw ddwaf::parsing_error("empty processor input mapping");
            }

            auto input = static_cast<raw_configuration::map>(inputs[0]);
            auto input_address = at<std::string>(input, "address");

            auto kp = at<std::vector<std::string>>(input, "key_path", {});
            for (const auto &path : kp) {
                if (path.empty()) {
                    throw ddwaf::parsing_error("empty key_path");
                }
            }

            parameters.emplace_back(
                processor_parameter{{processor_target{.index = get_target_index(input_address),
                    .name = std::move(input_address),
                    .key_path = kp}}});
        }
        auto output = at<std::string>(mapping, "output");
        mappings.emplace_back(processor_mapping{.inputs = std::move(parameters),
            .output = {
                .index = get_target_index(output), .name = std::move(output), .key_path = {}}});
    }

    return mappings;
}

} // namespace

void parse_processors(const raw_configuration::vector &processor_array,
    configuration_collector &cfg, ruleset_info::section_info &info)
{
    for (unsigned i = 0; i < processor_array.size(); i++) {
        const auto &node_param = processor_array[i];
        auto node = static_cast<raw_configuration::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (cfg.contains_processor(id)) {
                DDWAF_WARN("Duplicate processor: {}", id);
                info.add_failed(id, parser_error_severity::error, "duplicate processor");
                continue;
            }

            // Check version compatibility and fail without diagnostic
            auto min_version{at<semantic_version>(node, "min_version", semantic_version::min())};
            auto max_version{at<semantic_version>(node, "max_version", semantic_version::max())};
            if (min_version > current_version || max_version < current_version) {
                DDWAF_DEBUG(
                    "Skipping processor '{}': version required between [{}, {}], current {}", id,
                    min_version, max_version, current_version);
                info.add_skipped(id);
                continue;
            }

            processor_type type;
            auto generator_id = at<std::string>(node, "generator");
            if (generator_id == "extract_schema") {
                type = processor_type::extract_schema;
            } else if (generator_id == "http_endpoint_fingerprint") {
                type = processor_type::http_endpoint_fingerprint;
            } else if (generator_id == "http_network_fingerprint") {
                type = processor_type::http_network_fingerprint;
            } else if (generator_id == "http_header_fingerprint") {
                type = processor_type::http_header_fingerprint;
            } else if (generator_id == "session_fingerprint") {
                type = processor_type::session_fingerprint;
            } else if (generator_id == "jwt_decode") {
                type = processor_type::jwt_decode;
            } else if (generator_id == "uri_parse") {
                type = processor_type::uri_parse;
            } else {
                throw unknown_generator(generator_id);
            }

            auto conditions_array = at<raw_configuration::vector>(node, "conditions", {});
            auto expr = parse_simplified_expression(conditions_array);

            auto params = at<raw_configuration::map>(node, "parameters");
            auto mappings_vec = at<raw_configuration::vector>(params, "mappings");
            std::vector<processor_mapping> mappings;
            if (type == processor_type::extract_schema) {
                mappings = parse_processor_mappings(mappings_vec, extract_schema::param_names);
            } else if (type == processor_type::http_endpoint_fingerprint) {
                mappings =
                    parse_processor_mappings(mappings_vec, http_endpoint_fingerprint::param_names);
            } else if (type == processor_type::http_header_fingerprint) {
                mappings =
                    parse_processor_mappings(mappings_vec, http_header_fingerprint::param_names);
            } else if (type == processor_type::http_network_fingerprint) {
                mappings =
                    parse_processor_mappings(mappings_vec, http_network_fingerprint::param_names);
            } else if (type == processor_type::session_fingerprint) {
                mappings = parse_processor_mappings(mappings_vec, session_fingerprint::param_names);
            } else if (type == processor_type::jwt_decode) {
                mappings = parse_processor_mappings(mappings_vec, jwt_decode::param_names);
            } else {
                mappings = parse_processor_mappings(mappings_vec, uri_parse_processor::param_names);
            }

            std::vector<reference_spec> scanners;
            auto scanners_ref_array = at<raw_configuration::vector>(params, "scanners", {});
            if (!scanners_ref_array.empty()) {
                scanners.reserve(scanners_ref_array.size());
                for (const auto &ref : scanners_ref_array) {
                    scanners.emplace_back(
                        parse_reference(static_cast<raw_configuration::map>(ref)));
                }
            }

            auto eval = at<bool>(node, "evaluate", true);
            auto output = at<bool>(node, "output", false);

            if (!eval && !output) {
                DDWAF_WARN("Processor {} not used for evaluation or output", id);
                info.add_failed(id, parser_error_severity::error,
                    "processor not used for evaluation or output");
                continue;
            }
            const processor_spec spec{.type = type,
                .expr = std::move(expr),
                .mappings = std::move(mappings),
                .scanners = std::move(scanners),
                .evaluate = eval,
                .output = output};

            DDWAF_DEBUG("Parsed processor {}", id);
            info.add_loaded(id);
            cfg.emplace_processor(std::move(id), spec);
        } catch (const unsupported_operator_version &e) {
            DDWAF_WARN("Skipping processor '{}': {}", id, e.what());
            info.add_skipped(id);
        } catch (const parsing_exception &e) {
            DDWAF_WARN("Failed to parse processor '{}': {}", id, e.what());
            info.add_failed(i, id, e.severity(), e.what());
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse processor '{}': {}", id, e.what());
            info.add_failed(i, id, parser_error_severity::error, e.what());
        }
    }
}

} // namespace ddwaf
