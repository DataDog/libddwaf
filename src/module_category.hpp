// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace ddwaf {
enum class rule_module_category : uint8_t {
    network_acl = 0,
    authentication_acl,
    custom_acl,
    configuration,
    business_logic,
    rasp,
    waf,
};

constexpr std::size_t rule_module_count = static_cast<std::size_t>(rule_module_category::waf) + 1;

inline rule_module_category string_to_rule_module_category(std::string_view name)
{
    if (name == "network-acl") {
        return rule_module_category::network_acl;
    }
    if (name == "authentication-acl") {
        return rule_module_category::authentication_acl;
    }
    if (name == "custom-acl") {
        return rule_module_category::custom_acl;
    }
    if (name == "configuration") {
        return rule_module_category::configuration;
    }
    if (name == "business-logic") {
        return rule_module_category::business_logic;
    }
    if (name == "rasp") {
        return rule_module_category::rasp;
    }
    return rule_module_category::waf;
}

} // namespace ddwaf
