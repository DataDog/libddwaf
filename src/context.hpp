// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include <ddwaf.h>
#include <optional>
#include <rule.hpp>
#include <ruleset.hpp>
#include <config.hpp>
#include <utils.h>
#include <obfuscator.hpp>

namespace ddwaf
{

class context
{
public:
    context(ddwaf::ruleset &ruleset, ddwaf::config &config):
        ruleset_(ruleset), config_(config),
        store_(ruleset_.manifest, config_.free_fn)
    {
        status_cache_.reserve(ruleset_.rules.size());
    }

    context(const context&) = delete;
    context& operator=(const context&) = delete;
    context(context&&) = default;
    context& operator=(context&&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(ddwaf_object, optional_ref<ddwaf_result> res, uint64_t);

    bool run_collection(const std::string& name,
                 const ddwaf::rule_ref_vector& flow,
                 PWRetManager& manager,
                 const ddwaf::monotonic_clock::time_point& deadline);


protected:
    bool is_first_run() const { return status_cache_.empty(); }
    condition::status get_cached_status(ddwaf::rule::index_type rule_idx) const;
    bool has_new_targets(const std::vector<ddwaf::condition>& rules) const;

    ddwaf::ruleset &ruleset_;
    ddwaf::config &config_;
    ddwaf::object_store store_;

    std::unordered_map<rule::index_type, condition::status> status_cache_;
};

}
