// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {
template <typename T> std::vector<T> parse_data(parameter &input);

template <> std::vector<data_spec::value_type> parse_data<data_spec::value_type>(parameter &input)
{
    std::vector<data_spec::value_type> data;
    data.reserve(input.nbEntries);

    auto array = static_cast<parameter::vector>(input);
    for (const auto &values_param : array) {
        auto values = static_cast<parameter::map>(values_param);
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

bool parse_data(const parameter::vector &data_array, base_section_info &info, auto &&emplace_fn)
{
    bool data_parsed = false;
    for (unsigned i = 0; i < data_array.size(); ++i) {
        const ddwaf::parameter object = data_array[i];
        // TODO fix this id shenanigans
        std::string data_id;
        try {
            const auto entry = static_cast<ddwaf::parameter::map>(object);

            data_spec spec;
            spec.id = uuidv4_generate_pseudo();
            data_id = spec.data_id = at<std::string>(entry, "id");

            auto type_str = at<std::string_view>(entry, "type");
            spec.type = data_type_from_string(type_str);
            auto data = at<parameter>(entry, "data");

            if (spec.type == data_type::data_with_expiration ||
                spec.type == data_type::ip_with_expiration) {
                spec.values = parse_data<data_spec::value_type>(data);
            } else {
                DDWAF_DEBUG("Unknown type '{}' for data id '{}'", type_str, data_id);
                info.add_failed(data_id, "unknown type '" + std::string{type_str} + "'");
                continue;
            }

            DDWAF_DEBUG("Parsed dynamic data '{}' of type '{}'", data_id, type_str);
            data_parsed = true;
            info.add_loaded(data_id);
            emplace_fn(std::move(data_id), spec.id, std::move(spec));
        } catch (const ddwaf::exception &e) {
            if (data_id.empty()) {
                data_id = index_to_id(i);
            }

            DDWAF_ERROR("Failed to parse data id '{}': {}", data_id, e.what());
            info.add_failed(data_id, e.what());
        }
    }

    return data_parsed;
}

} // namespace

bool parse_rule_data(
    const parameter::vector &data_array, configuration_collector &cfg, base_section_info &info)
{
    return parse_data(
        data_array, info, [&cfg](std::string &&data_id, std::string id, data_spec &&data) {
            cfg.emplace_rule_data(std::move(data_id), std::move(id), std::move(data));
        });
}

bool parse_exclusion_data(
    const parameter::vector &data_array, configuration_collector &cfg, base_section_info &info)
{
    return parse_data(
        data_array, info, [&cfg](std::string &&data_id, std::string id, data_spec &&data) {
            cfg.emplace_exclusion_data(std::move(data_id), std::move(id), std::move(data));
        });
}

} // namespace ddwaf
