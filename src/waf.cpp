// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <unordered_map>

#include "clock.hpp"
#include <processor.hpp>
#include <PWRet.hpp>
#include <waf.hpp>
#include <ddwaf.h>
#include <exception.hpp>
#include <iostream>
#include <log.hpp>
#include <parameter.hpp>
#include <parser/parser.hpp>
#include <stdexcept>
#include <utils.h>

using namespace std::literals;

namespace ddwaf
{

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
        if (config->limits.max_container_size != 0)
        {
            limits.max_container_size = config->limits.max_container_size;
        }

        if (config->limits.max_container_depth != 0)
        {
            limits.max_container_depth = config->limits.max_container_depth;
        }


        if (config->limits.max_string_length != 0)
        {
            limits.max_string_length = config->limits.max_string_length;
        }
    }

    return limits;
}

}

waf::waf(ddwaf::manifest&& manifest_, rule_vector&& rules_,
        flow_map&& flows_, ddwaf_object_free_fn free_fn,
        ddwaf::obfuscator &&event_obfuscator_, object_limits limits_)
    : manifest(std::move(manifest_)),
      rules(std::move(rules_)),
      flows(std::move(flows_)),
      obj_free(free_fn),
      event_obfuscator(std::move(event_obfuscator_)),
      limits(limits_)
{}

waf* waf::fromConfig(const ddwaf_object ruleset,
    const ddwaf_config* config, ddwaf::ruleset_info& info)
{
    ddwaf::manifest_builder mb;
    rule_vector rules;
    flow_map flows;
    obfuscator obf = obfuscator_from_config(config);
    object_limits limits = limits_from_config(config);
    ddwaf_object_free_fn free_fn = config ? config->free_fn : ddwaf_object_free;
    try
    {
        parser::parse(ruleset, info, rules, mb, flows);
        return new waf(mb.build_manifest(), std::move(rules),
                     std::move(flows), free_fn, std::move(obf), limits);
    }
    catch (const std::exception& e)
    {
        DDWAF_ERROR("%s", e.what());
    }

    return nullptr;
}

ddwaf::context waf::get_context() {
    return ddwaf::context(manifest, flows, event_obfuscator, limits, obj_free);
}
}
