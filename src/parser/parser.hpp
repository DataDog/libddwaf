// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <manifest.hpp>
#include <parameter.hpp>
#include <rule.hpp>
#include <ruleset_info.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddwaf::parser
{

void parse(parameter ruleset, ruleset_info& info, rule_vector& rules,
           ddwaf::manifest_builder& mb, flow_map& flows);

}
