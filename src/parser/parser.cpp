// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <exception.hpp>
#include <log.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <string_view>

namespace ddwaf::parser {

unsigned parse_schema_version(parameter::map &ruleset)
{
    auto version = at<std::string_view>(ruleset, "version");

    auto dot_pos = version.find('.');
    if (dot_pos == std::string_view::npos) {
        throw parsing_error("invalid version format, expected major.minor");
    }
    version.remove_suffix(version.size() - dot_pos);

    unsigned major;
    if (std::from_chars(version.begin(), version.end(), major).ec != std::errc{}) {
        throw parsing_error("invalid version format, expected major.minor");
    }

    return major;
}

void parse(parameter object, ruleset_info &info, ddwaf::ruleset &rs, object_limits limits)
{
    parameter::map ruleset = object;
    auto version = at<std::string_view>(ruleset, "version");

    auto dot_pos = version.find('.');
    if (dot_pos == std::string_view::npos) {
        throw parsing_error("invalid version format, expected major.minor");
    }
    version.remove_suffix(version.size() - dot_pos);

    int major;
    if (std::from_chars(version.begin(), version.end(), major).ec != std::errc{}) {
        throw parsing_error("invalid version format, expected major.minor");
    }

    switch (major) {
    case 1:
        return v1::parse(ruleset, info, rs, limits);
    case 2:
        return v2::parse(ruleset, info, rs, limits);
    default:
        DDWAF_ERROR("incompatible ruleset version %u.x", major);
        throw unsupported_version();
    }
}

} // namespace ddwaf::parser
