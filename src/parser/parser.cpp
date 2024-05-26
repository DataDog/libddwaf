// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <string_view>

#include "exception.hpp"
#include "log.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"

namespace ddwaf::parser {

unsigned parse_schema_version(const std::unordered_map<std::string_view, object_view> &ruleset)
{
    auto version = at<std::string_view>(ruleset, "version");

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

} // namespace ddwaf::parser
