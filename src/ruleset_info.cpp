// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string_view>

#include "configuration/common/parser_exception.hpp"
#include "object.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

void ruleset_info::section_info::add_loaded(std::string_view id) { loaded_.emplace_back(id); }

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void ruleset_info::section_info::add_failed(
    std::string_view id, parser_error_severity sev, std::string_view error)
{
    const auto &inserter = [](auto &id, auto &error, auto &cache, auto &diagnostics_array,
                               auto &failed_array) {
        auto it = cache.find(error);
        if (it == cache.end()) {
            auto array = diagnostics_array.emplace(
                error, owned_object::make_array(0, diagnostics_array.alloc()));
            auto index = diagnostics_array.size() - 1;

            auto key = object_view{diagnostics_array}.at_key(index);
            cache[key.template as<std::string_view>()] = index;

            array.emplace_back(id);
        } else {
            diagnostics_array.at(it->second).emplace_back(id);
        }

        failed_array.emplace_back(id);
    };

    if (sev == parser_error_severity::error) {
        inserter(id, error, error_obj_cache_, errors_, failed_);
    } else {
        inserter(id, error, warning_obj_cache_, warnings_, failed_);
    }
}

void ruleset_info::section_info::add_skipped(std::string_view id) { skipped_.emplace_back(id); }

} // namespace ddwaf
