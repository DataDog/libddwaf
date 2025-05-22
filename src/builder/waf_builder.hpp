// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <utility>

#include "builder/ruleset_builder.hpp"
#include "configuration/configuration_manager.hpp"
#include "waf.hpp"

namespace ddwaf {

class waf_builder {
public:
    waf_builder(object_limits limits, ddwaf_object_free_fn free_fn,
        std::shared_ptr<match_obfuscator> obfuscator)
        : rbuilder_(limits, free_fn, std::move(obfuscator))
    {}

    ~waf_builder() = default;
    waf_builder(waf_builder &&) = delete;
    waf_builder(const waf_builder &) = delete;
    waf_builder &operator=(waf_builder &&) = delete;
    waf_builder &operator=(const waf_builder &) = delete;

    bool add_or_update(const std::string &path, raw_configuration &root, base_ruleset_info &info)
    {
        return cfg_mgr_.add_or_update(path, root, info);
    }

    bool remove(const std::string &path) { return cfg_mgr_.remove(path); }

    ddwaf::waf build()
    {
        auto [global_config, current_changes] = cfg_mgr_.consolidate();
        auto ruleset = rbuilder_.build(global_config, current_changes);
        return waf{std::move(ruleset)};
    }

    std::vector<std::string_view> get_filtered_config_paths(re2::RE2 &filter) const
    {
        return cfg_mgr_.get_filtered_config_paths(filter);
    }

    std::vector<std::string_view> get_config_paths() const { return cfg_mgr_.get_config_paths(); }

protected:
    configuration_manager cfg_mgr_;
    ruleset_builder rbuilder_;
};

} // namespace ddwaf
