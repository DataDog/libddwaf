// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <memory>

#include "ddwaf.h"
#include "parser/parser.hpp"
#include "context.hpp"
#include "ruleset.hpp"
#include "ruleset_builder.hpp"
#include "ruleset_info.hpp"
#include "utils.hpp"
#include "version.hpp"

namespace ddwaf {

class waf {
public:
    waf(ddwaf::parameter input, ddwaf::base_ruleset_info &info, ddwaf::object_limits limits,
        ddwaf_object_free_fn free_fn, std::shared_ptr<ddwaf::obfuscator> event_obfuscator);
    waf *update(ddwaf::parameter input, ddwaf::base_ruleset_info &info);

    ddwaf::context_wrapper *create_context() { return new context_wrapper(ruleset_); }

    [[nodiscard]] const std::vector<const char *> &get_root_addresses() const
    {
        return ruleset_->get_root_addresses();
    }

protected:
    waf(std::shared_ptr<ruleset_builder> builder, std::shared_ptr<ruleset> ruleset)
        : builder_(std::move(builder)), ruleset_(std::move(ruleset))
    {}

    std::shared_ptr<ruleset_builder> builder_;
    std::shared_ptr<ruleset> ruleset_;
};

} // namespace ddwaf
