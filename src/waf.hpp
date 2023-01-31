// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

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
    using ptr = std::shared_ptr<waf>;

    waf(ddwaf::ruleset &&ruleset, ddwaf::config &&config)
        : ruleset_(std::move(ruleset)), config_(std::move(config))
    {}

    static waf *from_config(
        const ddwaf_object &rules, const ddwaf_config *config, ddwaf::ruleset_info &info);

    ddwaf::context create_context() { return {ruleset_, config_}; }

    void update_rule_data(ddwaf::parameter::vector &&input) { ruleset_.dispatcher.dispatch(input); }

    void toggle_rules(ddwaf::parameter::map &&input);

    const std::vector<const char *> &get_root_addresses() const
    {
        return ruleset_.manifest.get_root_addresses();
    }
    const std::vector<const char *> &get_rule_data_ids()
    {
        return ruleset_.dispatcher.get_rule_data_ids();
    }

protected:
    ddwaf::ruleset ruleset_;
    ddwaf::config config_;
};

} // namespace ddwaf
