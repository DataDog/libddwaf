// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "waf.hpp"

namespace ddwaf {

waf::waf(ddwaf::parameter input, ddwaf::base_ruleset_info &info, ddwaf::object_limits limits,
    ddwaf_object_free_fn free_fn, std::shared_ptr<ddwaf::obfuscator> event_obfuscator)
{
    auto input_map = static_cast<parameter::map>(input);

    unsigned version = 2;

    auto it = input_map.find("version");
    if (it != input_map.end()) {
        try {
            version = parser::parse_schema_version(input_map);
        } catch (const std::exception &e) {
            DDWAF_DEBUG("Failed to parse version (defaulting to 2): {}", e.what());
        }
    }

    // Prevent combining version 1 of the ruleset and the builder
    if (version == 1) {
        ddwaf::ruleset rs;
        rs.free_fn = free_fn;
        rs.event_obfuscator = event_obfuscator;
        rs.actions = std::make_shared<action_mapper>();
        DDWAF_DEBUG("Parsing ruleset with schema version 1.x");
        parser::v1::parse(input_map, info, rs, limits);
        ruleset_ = std::make_shared<ddwaf::ruleset>(std::move(rs));
        return;
    }

    if (version == 2) {
        DDWAF_DEBUG("Parsing ruleset with schema version 2.x");
        builder_ = std::make_shared<ruleset_builder>(limits, free_fn, std::move(event_obfuscator));
        ruleset_ = builder_->build(input, info);
        if (!ruleset_) {
            throw std::runtime_error("failed to instantiate WAF");
        }
        return;
    }

    DDWAF_ERROR("incompatible ruleset schema version {}.x", version);

    throw unsupported_version();
}

waf *waf::update(ddwaf::parameter input, ddwaf::base_ruleset_info &info)
{
    if (builder_) {
        auto ruleset = builder_->build(input, info);
        if (ruleset) {
            return new waf{builder_, std::move(ruleset)};
        }
    }
    return nullptr;
}

} // namespace ddwaf
