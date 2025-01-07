// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "builder/waf_builder.hpp"
#include "configuration/configuration_manager.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"
#include "waf.hpp"
#include <string>
#include <utility>

namespace ddwaf {

bool waf_builder::add_or_update(
    const std::string &path, parameter::map &root, base_ruleset_info &info)
{
    return cfg_mgr_.add_or_update(path, root, info);
}

bool waf_builder::remove(const std::string &path) { return cfg_mgr_.remove(path); }

ddwaf::waf waf_builder::build()
{
    auto config = cfg_mgr_.consolidate();
    auto ruleset = rbuilder_.build(config);
    return waf{std::move(ruleset)};
}

} // namespace ddwaf
