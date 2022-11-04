// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <exclusion_filter.hpp>
#include <manifest.hpp>
#include <rule.hpp>
#include <rule_data_dispatcher.hpp>

namespace ddwaf
{

struct ruleset
{
    ddwaf::manifest manifest;
    ddwaf::exclusion_filter_vector filters;
    std::unordered_map<std::string, std::shared_ptr<ddwaf::rule>> rules;
    std::unordered_set<std::shared_ptr<ddwaf::rule>> rule_set;
    ddwaf::rule_data::dispatcher dispatcher;
};

} // namespace ddwaf
