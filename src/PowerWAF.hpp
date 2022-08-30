// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <obfuscator.hpp>
#include <PWManifest.h>
#include <rule.hpp>
#include <ruleset_info.hpp>
#include <utils.h>
#include <validator.hpp>

class PowerWAF
{
public:
    PowerWAF(PWManifest&& manifest_, ddwaf::rule_vector&& rules_,
             ddwaf::flow_map&& flows_, ddwaf::obfuscator &&event_obfuscator_,
             ddwaf::object_limits limits_ = ddwaf::object_limits());

    static PowerWAF* fromConfig(const ddwaf_object rules,
                                const ddwaf_config* config, ddwaf::ruleset_info& info);

    static constexpr ddwaf_version waf_version { 1, 4, 1 };

    PWManifest manifest;
    ddwaf::rule_vector rules;
    ddwaf::flow_map flows;

    ddwaf::obfuscator event_obfuscator;
    ddwaf::object_limits limits;
};
