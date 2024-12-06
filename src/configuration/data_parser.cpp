// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "configuration/common.hpp"
#include "configuration/configuration.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "parameter.hpp"

namespace ddwaf {

namespace {
using data_with_expiration = std::vector<std::pair<std::string_view, uint64_t>>;

template <typename T> T parse_data(std::string_view type, parameter &input);

template <>
data_with_expiration parse_data<data_with_expiration>(std::string_view type, parameter &input)
{
    if (type != "ip_with_expiration" && type != "data_with_expiration") {
        return {};
    }

    data_with_expiration data;
    data.reserve(input.nbEntries);

    auto array = static_cast<parameter::vector>(input);
    for (const auto &values_param : array) {
        auto values = static_cast<parameter::map>(values_param);
        data.emplace_back(
            at<std::string_view>(values, "value"), at<uint64_t>(values, "expiration", 0));
    }

    return data;
}

} // namespace

data_container parse_data(parameter::vector &data_array, base_section_info &info)
{
    data_container matchers;
    for (unsigned i = 0; i < data_array.size(); ++i) {
        const ddwaf::parameter object = data_array[i];
        std::string id;
        try {
            const auto entry = static_cast<ddwaf::parameter::map>(object);

            id = at<std::string>(entry, "id");

            auto type = at<std::string_view>(entry, "type");
            auto data = at<parameter>(entry, "data");

            std::string_view matcher_name;
            if (type == "ip_with_expiration") {
                matcher_name = "ip_match";
            } else if (type == "data_with_expiration") {
                matcher_name = "exact_match";
            } else {
                info.add_failed(id, "failed to infer matcher");
                continue;
            }

            std::shared_ptr<matcher::base> matcher;
            if (type == "ip_with_expiration") {
                using data_type = matcher::ip_match::data_type;
                auto parsed_data = parse_data<data_type>(type, data);
                matcher = std::make_shared<matcher::ip_match>(parsed_data);
            } else if (type == "data_with_expiration") {
                using data_type = matcher::exact_match::data_type;
                auto parsed_data = parse_data<data_type>(type, data);
                matcher = std::make_shared<matcher::exact_match>(parsed_data);
            } else {
                DDWAF_DEBUG("Unknown type '{}' for data id '{}", type, id);
                info.add_failed(id, "unkonwn type '" + std::string{type} + "'");
                continue;
            }

            DDWAF_DEBUG("Parsed dynamic data {}", id);
            info.add_loaded(id);
            matchers.emplace_back(data_spec{std::move(id), std::move(matcher)});
        } catch (const ddwaf::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }

            DDWAF_ERROR("Failed to parse data id '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return matchers;
}

} // namespace ddwaf
