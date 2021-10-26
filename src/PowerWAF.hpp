// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef pw_hpp
#define pw_hpp

#include <PWManifest.h>
#include <rule.hpp>
#include <utils.h>

struct PowerWAF
{
    uint64_t maxMapDepth { DDWAF_MAX_MAP_DEPTH };
    uint64_t maxArrayLength { DDWAF_MAX_ARRAY_LENGTH };

    // Maximum number of rules to report the time for
    uint32_t maxTimeStore { TIME_STORE_DEFAULT };

    PWManifest manifest;
    ddwaf::rule_map rules;
    ddwaf::flow_map flows;

    PowerWAF(PWManifest&& manifest_, ddwaf::rule_map&& rules_,
             ddwaf::flow_map&& flows_, const ddwaf_config* config);

    static PowerWAF* fromConfig(const ddwaf_object rules, const ddwaf_config* config);

    static constexpr ddwaf_version waf_version { 1, 0, 13 };
};

#endif /* pw_hpp */
