// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "builder/processor_builder.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "processor/base.hpp"
#include <vector>

namespace ddwaf::parser::v2 {

namespace {
std::vector<processor_mapping> parse_processor_mappings(
    const parameter::vector &root, address_container &addresses)
{
    if (root.empty()) {
        throw ddwaf::parsing_error("empty mappings");
    }

    std::vector<processor_mapping> mappings;
    for (const auto &node : root) {
        auto mapping = static_cast<parameter::map>(node);

        // TODO support n:1 mappings and key paths
        auto inputs = at<parameter::vector>(mapping, "inputs");
        if (inputs.empty()) {
            throw ddwaf::parsing_error("empty processor input mapping");
        }

        auto input = static_cast<parameter::map>(inputs[0]);
        auto input_address = at<std::string>(input, "address");
        auto output = at<std::string>(mapping, "output");

        addresses.optional.emplace(input_address);

        mappings.emplace_back(processor_mapping{
            {processor_parameter{
                {processor_target{get_target_index(input_address), std::move(input_address), {}}}}},
            {get_target_index(output), std::move(output), {}}});
    }

    return mappings;
}

} // namespace

processor_container parse_processors(
    parameter::vector &processor_array, base_section_info &info, const object_limits &limits)
{
    processor_container processors;
    std::unordered_set<std::string> known_processors;

    for (unsigned i = 0; i < processor_array.size(); i++) {
        const auto &node_param = processor_array[i];
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            address_container addresses;

            id = at<std::string>(node, "id");
            if (known_processors.contains(id)) {
                DDWAF_WARN("Duplicate processor: {}", id);
                info.add_failed(id, "duplicate processor");
                continue;
            }

            processor_type type;
            auto generator_id = at<std::string>(node, "generator");
            if (generator_id == "extract_schema") {
                type = processor_type::extract_schema;
            } else {
                DDWAF_WARN("Unknown generator: {}", generator_id);
                info.add_failed(id, "unknown generator '" + generator_id + "'");
                continue;
            }

            auto conditions_array = at<parameter::vector>(node, "conditions", {});
            auto expr = parse_simplified_expression(conditions_array, addresses, limits);

            auto params = at<parameter::map>(node, "parameters");
            auto mappings_vec = at<parameter::vector>(params, "mappings");
            auto mappings = parse_processor_mappings(mappings_vec, addresses);

            std::vector<reference_spec> scanners;
            auto scanners_ref_array = at<parameter::vector>(params, "scanners", {});
            if (!scanners_ref_array.empty()) {
                scanners.reserve(scanners_ref_array.size());
                for (const auto &ref : scanners_ref_array) {
                    scanners.emplace_back(parse_reference(static_cast<parameter::map>(ref)));
                }
            }

            auto eval = at<bool>(node, "evaluate", true);
            auto output = at<bool>(node, "output", false);

            if (!eval && !output) {
                DDWAF_WARN("Processor {} not used for evaluation or output", id);
                info.add_failed(id, "processor not used for evaluation or output");
                continue;
            }

            DDWAF_DEBUG("Parsed processor {}", id);
            known_processors.emplace(id);
            info.add_loaded(id);
            add_addresses_to_info(addresses, info);

            if (eval) {
                processors.pre.emplace_back(processor_builder{type, std::move(id), std::move(expr),
                    std::move(mappings), std::move(scanners), eval, output});
            } else {
                processors.post.emplace_back(processor_builder{type, std::move(id), std::move(expr),
                    std::move(mappings), std::move(scanners), eval, output});
            }

        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse processor '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }
    return processors;
}

} // namespace ddwaf::parser::v2
