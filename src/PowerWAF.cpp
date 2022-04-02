// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <unordered_map>

#include "clock.hpp"
#include <PWProcessor.hpp>
#include <PWRet.hpp>
#include <PWRetriever.hpp>
#include <PowerWAF.hpp>
#include <ddwaf.h>
#include <exception.hpp>
#include <iostream>
#include <log.hpp>
#include <parameter.hpp>
#include <parser/parser.hpp>
#include <stdexcept>
#include <utils.h>

using namespace ddwaf;
using namespace std::literals;

namespace {
obfuscator obfuscator_from_config(const ddwaf_config* config)
{
    std::string_view key_regex, value_regex;

    if (config != nullptr) {
        if (config->obfuscator.key_regex) {
            key_regex = config->obfuscator.key_regex;
        }

        if (config->obfuscator.value_regex) {
            value_regex = config->obfuscator.value_regex;
        }
    }

    return obfuscator(key_regex, value_regex);
}

ddwaf::object_limits limits_from_config(const ddwaf_config *config)
{
    ddwaf::object_limits limits;

    if (config != nullptr) {
        if (config->limits.max_array_size != 0)
        {
            limits.max_array_size = config->limits.max_array_size;
        }

        if (config->limits.max_map_depth != 0)
        {
            limits.max_map_depth = config->limits.max_map_depth;
        }


        if (config->limits.max_string_length != 0)
        {
            limits.max_string_length = config->limits.max_string_length;
        }
    }

    return limits;
}

}

PowerWAF::PowerWAF(PWManifest&& manifest_, rule_vector&& rules_,
                   flow_map&& flows_, ddwaf::obfuscator &&event_obfuscator_,
                   object_limits limits_)
    : manifest(std::move(manifest_)),
      rules(std::move(rules_)),
      flows(std::move(flows_)),
      event_obfuscator(std::move(event_obfuscator_)),
      limits(limits_)
{}

PowerWAF* PowerWAF::fromConfig(const ddwaf_object ruleset,
                               const ddwaf_config* config, ddwaf::ruleset_info& info)
{
    PWManifest manifest;
    rule_vector rules;
    flow_map flows;
    obfuscator obf = obfuscator_from_config(config);
    object_limits limits = limits_from_config(config);

    try
    {
        parser::parse(ruleset, info, rules, manifest, flows);
        return new PowerWAF(std::move(manifest), std::move(rules),
                            std::move(flows), std::move(obf), limits);
    }
    catch (const std::exception& e)
    {
        DDWAF_ERROR("%s", e.what());
    }

    return nullptr;
}
