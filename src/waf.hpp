// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <context.hpp>
#include <obfuscator.hpp>
#include <limits.hpp>
#include <manifest.hpp>
#include <rule.hpp>
#include <ruleset_info.hpp>
#include <utils.h>
#include <version.hpp>

namespace ddwaf
{

class waf
{
public:
    waf(ddwaf::manifest&& manifest_, ddwaf::rule_vector&& rules_,
             ddwaf::flow_map&& flows_, ddwaf_object_free_fn free_fn,
             ddwaf::obfuscator &&event_obfuscator_,
             ddwaf::object_limits limits_ = ddwaf::object_limits());

    static waf* fromConfig(const ddwaf_object rules,
        const ddwaf_config* config, ddwaf::ruleset_info& info);

    ddwaf::context get_context();

    ddwaf::manifest manifest;
    ddwaf::rule_vector rules;
    ddwaf::flow_map flows;
    ddwaf_object_free_fn obj_free;

    const ddwaf::obfuscator event_obfuscator;
    const ddwaf::object_limits limits;
};

}
