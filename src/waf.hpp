// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include "ddwaf.h"
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
        : builder_(limits, free_fn, std::move(event_obfuscator))
    {
        ruleset_ = builder_.build(input, info);
    }

    void update(ddwaf::parameter input, ddwaf::ruleset_info &info)
    {
        auto new_ruleset = builder_.build(input, info);
        if (new_ruleset) {
            ruleset_ = new_ruleset;
        }
    }

    ddwaf::context create_context() { return context{ruleset_}; }

    [[nodiscard]] const std::vector<const char *> &get_root_addresses() const
    {
        return ruleset_->manifest.get_root_addresses();
    }

protected:
    ddwaf::builder builder_;
    std::shared_ptr<ruleset> ruleset_;
};

} // namespace ddwaf
