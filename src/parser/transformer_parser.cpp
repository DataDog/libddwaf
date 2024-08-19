// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/common.hpp"
#include <memory>

namespace ddwaf::parser::v2 {

std::vector<transformer_id> parse_transformers(const parameter::vector &root, data_source &source)
{
    if (root.empty()) {
        return {};
    }

    std::vector<transformer_id> transformers;
    transformers.reserve(root.size());

    for (const auto &transformer_param : root) {
        auto transformer = static_cast<std::string_view>(transformer_param);
        auto id = transformer_from_string(transformer);
        if (id.has_value()) {
            transformers.emplace_back(id.value());
        } else if (transformer == "keys_only") {
            source = ddwaf::data_source::keys;
        } else if (transformer == "values_only") {
            source = ddwaf::data_source::values;
        } else {
            throw ddwaf::parsing_error("invalid transformer " + std::string(transformer));
        }
    }
    return transformers;
}

std::vector<transformer_id> parse_transformers(const parameter::vector &root)
{
    if (root.empty()) {
        return {};
    }

    std::vector<transformer_id> transformers;
    transformers.reserve(root.size());

    for (const auto &transformer_param : root) {
        auto transformer = static_cast<std::string_view>(transformer_param);
        auto id = transformer_from_string(transformer);
        if (id.has_value()) {
            transformers.emplace_back(id.value());
        } else if (transformer == "keys_only" || transformer == "values_only") {
            throw ddwaf::parsing_error("source transformer not supported within this context");
        } else {
            throw ddwaf::parsing_error("invalid transformer " + std::string(transformer));
        }
    }
    return transformers;
}

} // namespace ddwaf::parser::v2
