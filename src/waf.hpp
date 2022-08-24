// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <config.hpp>
#include <context.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <utils.h>
#include <version.hpp>

namespace ddwaf
{

class waf
{
public:
    waf(ddwaf::ruleset &&ruleset, ddwaf::config &&config):
        ruleset_(std::move(ruleset)), config_(std::move(config)) {}

    static waf* from_config(const ddwaf_object rules,
        const ddwaf_config* config, ddwaf::ruleset_info& info);

    ddwaf::context create_context() const {
        return ddwaf::context(ruleset_, config_);
    }

    void update_rule_data(ddwaf::parameter::vector &&input){
        ruleset_.dispatcher.dispatch(input);
    }

    const std::vector<const char*>& get_root_addresses() const {
        return ruleset_.manifest.get_root_addresses();
    }
protected:
    ddwaf::ruleset ruleset_;
    ddwaf::config config_;
};

}
