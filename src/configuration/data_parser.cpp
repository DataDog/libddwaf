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
#include "exception.hpp"
#include "log.hpp"
#include "parameter.hpp"

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

std::vector<data_spec> parse_data(const parameter::vector &data_array, base_section_info &info)
{
    std::vector<data_spec> all_data;
    for (unsigned i = 0; i < data_array.size(); ++i) {
        const ddwaf::parameter object = data_array[i];
        std::string id;
        try {
            const auto entry = static_cast<ddwaf::parameter::map>(object);

            data_spec spec;
            spec.id = at<std::string>(entry, "id");

            auto type_str = at<std::string_view>(entry, "type");
            spec.type = data_type_from_string(type_str);
            auto data = at<parameter>(entry, "data");

            if (spec.type == data_type::data_with_expiration ||
                spec.type == data_type::ip_with_expiration) {
                spec.values = parse_data<data_spec::value_type>(data);
            } else {
                DDWAF_DEBUG("Unknown type '{}' for data id '{}", type_str, id);
                info.add_failed(id, "unkonwn type '" + std::string{type_str} + "'");
                continue;
            }

            DDWAF_DEBUG("Parsed dynamic data {} of type {}", id, type_str);
            info.add_loaded(id);
            all_data.emplace_back(std::move(spec));
        } catch (const ddwaf::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }

            DDWAF_ERROR("Failed to parse data id '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return all_data;
}

} // namespace

bool parse_rule_data(
    const parameter::vector &data_array, configuration_spec &cfg, base_section_info &info)
{
    cfg.rule_data = parse_data(data_array, info);
    return !cfg.rule_data.empty();
}

bool parse_exclusion_data(
    const parameter::vector &data_array, configuration_spec &cfg, base_section_info &info)
{
    cfg.exclusion_data = parse_data(data_array, info);
    return !cfg.exclusion_data.empty();
}

} // namespace ddwaf
