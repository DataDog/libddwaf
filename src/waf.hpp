// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include "ddwaf.h"
#include "parser/parser.hpp"
#include <builder.hpp>
#include <config.hpp>
#include <context.hpp>
#include <memory>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <utils.hpp>
#include <version.hpp>

namespace ddwaf {

class waf {
public:
    waf(ddwaf::parameter input, ddwaf::ruleset_info &info, ddwaf::object_limits limits,
        ddwaf_object_free_fn free_fn, ddwaf::obfuscator event_obfuscator)
    {
        parameter::map input_map = input;

        unsigned version = 2;

        auto it = input_map.find("version");
        if (it != input_map.end()) {
            try {
                version = parser::parse_schema_version(input_map);
            } catch (const std::exception &e) {
                DDWAF_DEBUG("Failed to parse version (defaulting to 2): %s", e.what());
            }
        }

        // Prevent combining version 1 of the ruleset and the builder
        if (version == 1) {
            ddwaf::ruleset rs;
            parser::v1::parse(input_map, info, rs, limits);
            ruleset_ = std::make_shared<ddwaf::ruleset>(std::move(rs));
            return;
        }

        builder_ = std::make_shared<builder>(limits, free_fn, std::move(event_obfuscator));
        ruleset_ = builder_->build(input, info);
    }

    waf *update(ddwaf::parameter input, ddwaf::ruleset_info &info)
    {
        if (builder_) {
            auto ruleset = builder_->build(input, info);
            if (ruleset) {
                return new waf{builder_, std::move(ruleset)};
            }
        }
        return nullptr;
    }

    ddwaf::context create_context() { return context{ruleset_}; }

    [[nodiscard]] const std::vector<const char *> &get_root_addresses() const
    {
        return ruleset_->manifest.get_root_addresses();
    }

protected:
    waf(ddwaf::builder::ptr builder, ddwaf::ruleset::ptr ruleset)
        : builder_(std::move(builder)), ruleset_(std::move(ruleset))
    {}

    ddwaf::builder::ptr builder_;
    ddwaf::ruleset::ptr ruleset_;
};

} // namespace ddwaf
