// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef pw_hpp
#define pw_hpp

#include <PWManifest.h>
#include <memory>
#include <unordered_map>
#include <utils.h>

#include <PWRuleManager.hpp>

struct PowerWAF
{
    uint64_t maxMapDepth { DDWAF_MAX_MAP_DEPTH };
    uint64_t maxArrayLength { DDWAF_MAX_ARRAY_LENGTH };

    // Maximum number of rules to report the time for
    uint32_t maxTimeStore { TIME_STORE_DEFAULT };

    PWManifest manifest;
    PWRuleManager ruleManager;
    std::unordered_map<std::string, std::vector<std::string>> flows;

    PowerWAF(PWManifest&& manifest_, PWRuleManager&& ruleManager_,
             std::unordered_map<std::string, std::vector<std::string>>&& flows_,
             const ddwaf_config* config);

    static PowerWAF* fromConfig(const ddwaf_object rules, const ddwaf_config* config);

    static constexpr ddwaf_version ruleset_version { 1, 0, 0 };
    static constexpr ddwaf_version waf_version { 1, 0, 10 };
};

#endif /* pw_hpp */
