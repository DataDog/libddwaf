// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <builder.hpp>
#include <charconv>
#include <exception.hpp>
#include <log.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <string_view>

namespace ddwaf
{

std::shared_ptr<ruleset> builder::build(parameter object, ruleset_info &info, object_limits limits)
{
    parameter::map ruleset = object;

    ddwaf::ruleset rs;

    auto version = parser::parse_schema_version(ruleset);
    switch (version) {
    case 1:
        parser::v1::parse(ruleset, info, rs, limits);
        break;
    case 2:
        parser::v2::parse(ruleset, info, rs, limits);
        break;
    default:
        DDWAF_ERROR("incompatible ruleset version %u.x", version);
        throw unsupported_version();
    }

    return std::make_shared<ddwaf::ruleset>(std::move(rs));
}

} // namespace ddwaf
