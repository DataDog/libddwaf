// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>

#include "configuration/common/raw_configuration.hpp"
#include "exception.hpp"
#include "ruleset_info.hpp"

using base_section_info = ddwaf::base_ruleset_info::base_section_info;

namespace ddwaf {

template <typename T, typename Key = std::string>
T at(const raw_configuration::map &map, const Key &key)
{
    try {
        return static_cast<T>(map.at(key));
    } catch (const std::out_of_range &) {
        throw missing_key(std::string(key));
    } catch (const bad_cast &e) {
        throw invalid_type(std::string(key), e);
    }
}

template <typename T, typename Key>
T at(const raw_configuration::map &map, const Key &key, const T &default_)
{
    try {
        auto it = map.find(key);
        return it == map.end() ? default_ : static_cast<T>(it->second);
    } catch (const bad_cast &e) {
        throw invalid_type(std::string(key), e);
    }
}

inline std::string index_to_id(unsigned idx) { return "index:" + to_string<std::string>(idx); }

inline unsigned parse_schema_version(raw_configuration::map &ruleset)
{
    auto version = at<std::string_view>(ruleset, "version", {});
    if (version.empty()) {
        return 2;
    }

    auto dot_pos = version.find('.');
    if (dot_pos == std::string_view::npos) {
        throw parsing_error("invalid version format, expected major.minor");
    }
    version.remove_suffix(version.size() - dot_pos);

    unsigned major;
    const char *data = version.data();
    const char *end = data + version.size();
    if (std::from_chars(data, end, major).ec != std::errc{}) {
        throw parsing_error("invalid version format, expected major.minor");
    }

    return major;
}

} // namespace ddwaf
