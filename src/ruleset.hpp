// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <manifest.hpp>
#include <rule.hpp>
#include <rule_data_dispatcher.hpp>

namespace ddwaf
{

struct ruleset
{
    ddwaf::manifest manifest;
    ddwaf::rule_vector rules;
    ddwaf::rule_ref_map rule_map;
    ddwaf::collection_map collections;
    ddwaf::rule_data::dispatcher dispatcher;
};

} // namespace ddwaf
