// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/data_parser.hpp"
#include "expiring_string_list.hpp"
#include "log.hpp"
#include "object.hpp"
#include "ruleset_info.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {

// Parses the entries of a data set, i.e. an array of maps with a mandatory
// "value" and an optional "expiration". Data sets can have hundreds of
// thousands of entries, so they are read straight from the object view rather
// than through raw_configuration::map, which would build a hash map per entry,
// and all values are copied into a single buffer. Errors are reported exactly
// as the generic accessors do.
expiring_string_list parse_values(const raw_configuration &input)
{
    const auto input_view = static_cast<object_view>(input);
    if (!input_view.is_array()) {
        // Throws the appropriate bad_cast
        static_cast<void>(static_cast<raw_configuration::vector>(input));
    }

    const array_view array{input_view};
    expiring_string_list values;
    values.reserve(array.size());
    for (const auto view : array) {
        if (!view.is_map()) {
            // Throws the appropriate bad_cast
            static_cast<void>(static_cast<raw_configuration::map>(raw_configuration{view}));
        }

        // As with raw_configuration::map, all keys are validated beforehand
        // and the first occurrence of a duplicate key prevails.
        object_view value;
        object_view expiration;
        for (auto [key, val] : map_view{view}) {
            if (key.empty()) {
                throw malformed_object("invalid key on map entry");
            }

            const auto key_str = key.as<std::string_view>();
            if (!value.has_value() && key_str == "value") {
                value = val;
            } else if (!expiration.has_value() && key_str == "expiration") {
                expiration = val;
            }
        }

        if (!value.has_value()) {
            throw missing_key("value");
        }

        std::string_view str;
        std::string converted;
        if (value.is_string()) {
            str = value.as<std::string_view>();
        } else {
            try {
                converted = static_cast<std::string>(raw_configuration{value});
            } catch (const bad_cast &e) {
                throw invalid_type("value", e);
            }
            str = converted;
        }

        uint64_t expiration_value = 0;
        if (expiration.has_value()) {
            try {
                expiration_value = static_cast<uint64_t>(raw_configuration{expiration});
            } catch (const bad_cast &e) {
                throw invalid_type("expiration", e);
            }
        }

        values.emplace_back(str, expiration_value);
    }

    return values;
}

data_type data_type_from_string(std::string_view str_type)
{
    if (str_type == "ip_with_expiration") {
        return data_type::ip_with_expiration;
    }

    if (str_type == "data_with_expiration") {
        return data_type::data_with_expiration;
    }

    return data_type::unknown;
}

void parse_data(const raw_configuration::vector &data_array, ruleset_info::section_info &info,
    auto &&emplace_fn)
{
    for (unsigned i = 0; i < data_array.size(); ++i) {
        const ddwaf::raw_configuration object = data_array[i];
        std::string data_id;
        try {
            const auto entry = static_cast<ddwaf::raw_configuration::map>(object);

            std::string id = uuidv4_generate_pseudo();
            data_id = at<std::string>(entry, "id");

            auto type_str = at<std::string_view>(entry, "type");
            auto type = data_type_from_string(type_str);
            auto data = at<raw_configuration>(entry, "data");
            if (type != data_type::data_with_expiration && type != data_type::ip_with_expiration) {
                DDWAF_DEBUG("Unknown type '{}' for data id '{}'", type_str, data_id);
                info.add_failed(data_id, parser_error_severity::error,
                    "unknown type: '" + std::string{type_str} + "'");
                continue;
            }
            auto values = parse_values(data);

            DDWAF_DEBUG("Parsed dynamic data '{}' of type '{}'", data_id, type_str);
            info.add_loaded(data_id);
            emplace_fn(std::move(data_id), std::move(id), type, std::move(values));
        } catch (const parsing_exception &e) {
            DDWAF_ERROR("Failed to parse data id '{}': {}", data_id, e.what());
            info.add_failed(i, data_id, e.severity(), e.what());
        } catch (const std::exception &e) {
            DDWAF_ERROR("Failed to parse data id '{}': {}", data_id, e.what());
            info.add_failed(i, data_id, parser_error_severity::error, e.what());
        }
    }
}

} // namespace

void parse_rule_data(const raw_configuration::vector &data_array, configuration_collector &cfg,
    ruleset_info::section_info &info)
{
    parse_data(data_array, info,
        [&cfg](std::string &&data_id, std::string &&id, data_type type,
            expiring_string_list &&data) {
            cfg.emplace_rule_data(std::move(data_id), std::move(id), type, std::move(data));
        });
}

void parse_exclusion_data(const raw_configuration::vector &data_array, configuration_collector &cfg,
    ruleset_info::section_info &info)
{
    parse_data(data_array, info,
        [&cfg](std::string &&data_id, std::string &&id, data_type type,
            expiring_string_list &&data) {
            cfg.emplace_exclusion_data(std::move(data_id), std::move(id), type, std::move(data));
        });
}

} // namespace ddwaf
