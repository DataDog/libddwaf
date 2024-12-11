// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <utility>

#include "builder/ruleset_builder.hpp"
#include "configuration/manager.hpp"

namespace ddwaf {

class waf_builder {
public:
    waf_builder(object_limits limits, ddwaf_object_free_fn free_fn,
        std::shared_ptr<ddwaf::obfuscator> event_obfuscator)
        : rbuilder_(limits, free_fn, std::move(event_obfuscator))
    {}

    ~waf_builder() = default;
    waf_builder(waf_builder &&) = delete;
    waf_builder(const waf_builder &) = delete;
    waf_builder &operator=(waf_builder &&) = delete;
    waf_builder &operator=(const waf_builder &) = delete;

    bool add(const std::string &path, parameter::map &root, base_ruleset_info &info)
    {
        return cfg_mgr_.add(path, root, info);
    }

    bool update(const std::string &path, parameter::map &root, base_ruleset_info &info)
    {
        return cfg_mgr_.update(path, root, info);
    }

    bool remove(const std::string &path)
    {
        return cfg_mgr_.remove(path);
    }

    std::shared_ptr<ruleset> build()
    {
        auto config = cfg_mgr_.consolidate();
        return rbuilder_.build(config);
    }
protected:
    configuration_manager cfg_mgr_;
    ruleset_builder rbuilder_;
};

} // namespace ddwaf
