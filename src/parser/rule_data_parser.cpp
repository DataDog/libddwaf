// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/rule_data_parser.hpp"
#include "exception.hpp"

namespace ddwaf::parser {

using data_with_expiration = std::vector<std::pair<std::string_view, uint64_t>>;

template <>
data_with_expiration parse_rule_data<data_with_expiration>(std::string_view type, object_view input)
{
    if (type != "ip_with_expiration" && type != "data_with_expiration") {
        return {};
    }

    data_with_expiration data;
    data.reserve(input.size());

    auto array = input.convert<object_view::array>();
    for (auto values_param : array) {
        auto values = values_param.convert<std::unordered_map<std::string_view, object_view>>();
        data.emplace_back(
            at<std::string_view>(values, "value"), at<uint64_t>(values, "expiration", 0));
    }

    return data;
}

} // namespace ddwaf::parser
