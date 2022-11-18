// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <optional>

#include <config.hpp>
#include <ddwaf.h>
#include <event.hpp>
#include <exclusion_filter.hpp>
#include <obfuscator.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <utils.h>

namespace ddwaf {

class context {
public:
    context(ddwaf::ruleset &ruleset, const ddwaf::config &config)
        : ruleset_(ruleset), config_(config), store_(ruleset_.manifest, config_.free_fn)
    {
        rule_cache_.reserve(ruleset_.rules.size());
        filter_cache_.reserve(ruleset_.filters.size());
        collection_cache_.reserve(ruleset_.collections.size());
    }

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) = default;
    context &operator=(context &&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(const ddwaf_object &, optional_ref<ddwaf_result> res, uint64_t);

    std::set<rule_base::ptr> filter(ddwaf::timer &deadline);
    std::vector<event> match(const std::set<rule_base::ptr> &exclude, ddwaf::timer &deadline);

protected:
    bool is_first_run() const { return rule_cache_.empty(); }

    ddwaf::ruleset &ruleset_;
    const ddwaf::config &config_;
    ddwaf::object_store store_;

    // Cache of filters and conditions
    std::unordered_map<exclusion_filter::ptr, exclusion_filter::cache_type> filter_cache_;
    // Cache of rules and conditions
    std::unordered_map<rule_base::ptr, rule::cache_type> rule_cache_;
    // Cache of collections to avoid processing once a result has been obtained
    std::unordered_set<std::string> collection_cache_;
};

} // namespace ddwaf
