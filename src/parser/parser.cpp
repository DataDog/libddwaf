// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <iostream>
#include <log.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <string_view>

namespace ddwaf::parser
{

namespace v1
{
    void parse(parameter::map& ruleset, PWRuleManager& ruleManager, PWManifest& manifest,
               std::unordered_map<std::string, std::vector<std::string>>& flows);
}

namespace v2
{
    void parse(parameter::map& ruleset, PWRuleManager& ruleManager, PWManifest& manifest,
               std::unordered_map<std::string, std::vector<std::string>>& flows);
}

void parse(parameter rules, PWRuleManager& ruleManager, PWManifest& manifest,
           std::unordered_map<std::string, std::vector<std::string>>& flows)
{
    parameter::map ruleset   = parameter::map(rules);
    std::string_view version = at<std::string_view>(ruleset, "version");

    uint16_t major, minor;
    if (std::sscanf(version.data(), "%hu.%hu", &major, &minor) != 2)
    {
        throw parsing_error("invalid version format, expected major.minor");
    }

    switch (major)
    {
        case 1:
            return v1::parse(ruleset, ruleManager, manifest, flows);
        case 2:
            return v2::parse(ruleset, ruleManager, manifest, flows);
        default:
            DDWAF_ERROR("incompatible ruleset version %u.%u", major, minor);
            throw unsupported_version();
    }
}

}
