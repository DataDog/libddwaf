// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string>
#include <unordered_map>
#include <utility>

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/reference_parser.hpp"
#include "configuration/common/raw_configuration.hpp"

namespace ddwaf {

reference_spec parse_reference(const raw_configuration::map &target)
{
    auto ref_id = at<std::string>(target, "rule_id", {});
    if (!ref_id.empty()) {
        return {.type = reference_type::id, .ref_id = std::move(ref_id), .tags = {}};
    }

    ref_id = at<std::string>(target, "id", {});
    if (!ref_id.empty()) {
        return {.type = reference_type::id, .ref_id = std::move(ref_id), .tags = {}};
    }

    auto tag_map = at<raw_configuration::map>(target, "tags", {});
    if (!tag_map.empty()) {
        std::unordered_map<std::string, std::string> tags;
        for (auto &[key, value] : tag_map) { tags.emplace(key, value); }

        return {.type = reference_type::tags, .ref_id = {}, .tags = std::move(tags)};
    }

    return {.type = reference_type::none, .ref_id = {}, .tags = {}};
}

} // namespace ddwaf
