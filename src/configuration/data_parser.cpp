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
#include "log.hpp"
#include "ruleset_info.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {
template <typename T> std::vector<T> parse_data(raw_configuration &input);

template <>
std::vector<data_spec::value_type> parse_data<data_spec::value_type>(raw_configuration &input)
{
    std::vector<data_spec::value_type> data;
    data.reserve(input.nbEntries);

    auto array = static_cast<raw_configuration::vector>(input);
    for (const auto &values_param : array) {
        auto values = static_cast<raw_configuration::map>(values_param);
        data.emplace_back(at<std::string>(values, "value"), at<uint64_t>(values, "expiration", 0));
    }

    return data;
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
            auto values = parse_data<data_spec::value_type>(data);

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
            std::vector<data_spec::value_type> &&data) {
            cfg.emplace_rule_data(std::move(data_id), std::move(id), type, std::move(data));
        });
}

void parse_exclusion_data(const raw_configuration::vector &data_array, configuration_collector &cfg,
    ruleset_info::section_info &info)
{
    parse_data(data_array, info,
        [&cfg](std::string &&data_id, std::string &&id, data_type type,
            std::vector<data_spec::value_type> &&data) {
            cfg.emplace_exclusion_data(std::move(data_id), std::move(id), type, std::move(data));
        });
}

} // namespace ddwaf
