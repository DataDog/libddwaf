#include <iostream>
#include <string_view>
#include <log.hpp>
#include <exception.hpp>
#include <parser/parser.hpp>
#include <parser/v1/parser.hpp>
#include <parser/v2/parser.hpp>

namespace ddwaf::parser {

void parse(parameter& rules, PWRuleManager& ruleManager, PWManifest& manifest,
           std::unordered_map<std::string, std::vector<std::string>>& flows)
{
    uint16_t major, minor;

    parameter::map ruleset = rules;
    std::string_view version = at<std::string_view>(ruleset, "version");
    int ret = std::sscanf(version.data(), "%hu.%hu", &major, &minor);
    if (ret != 2)
    {
        throw parsing_error("invalid version format");
    }

    switch(major) {
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
