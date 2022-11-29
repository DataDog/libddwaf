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
#include <exclusion/input_filter.hpp>
#include <exclusion/rule_filter.hpp>
#include <obfuscator.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <utils.h>

namespace ddwaf {

class context {
public:
    using object_set = std::unordered_set<ddwaf_object *>;

    context(ddwaf::ruleset &ruleset, const ddwaf::config &config)
        : ruleset_(ruleset), config_(config), store_(ruleset_.manifest, config_.free_fn)
    {
        rule_cache_.reserve(ruleset_.rules.size());
        rule_filter_cache_.reserve(ruleset_.rule_filters.size());
        input_filter_cache_.reserve(ruleset_.input_filters.size());
        collection_cache_.reserve(ruleset_.collections.size());
    }

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) = default;
    context &operator=(context &&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(const ddwaf_object &, optional_ref<ddwaf_result> res, uint64_t);

    // These two functions below return references to internal objects,
    // however using them this way helps with testing
    const std::unordered_set<rule::ptr> &filter_rules(ddwaf::timer &deadline);
    const std::unordered_map<rule::ptr, object_set> &filter_inputs(
        const std::unordered_set<rule::ptr> &rules_to_exclude, ddwaf::timer &deadline);

    std::vector<event> match(const std::unordered_set<rule::ptr> &rules_to_exclude,
        const std::unordered_map<rule::ptr, object_set> &objects_to_exclude,
        ddwaf::timer &deadline);

protected:
    bool is_first_run() const { return rule_cache_.empty(); }

    ddwaf::ruleset &ruleset_;
    const ddwaf::config &config_;
    ddwaf::object_store store_;

    using input_filter = exclusion::input_filter;
    using rule_filter = exclusion::rule_filter;

    // Cache of filters and conditions
    std::unordered_map<rule_filter::ptr, rule_filter::cache_type> rule_filter_cache_;
    std::unordered_map<input_filter::ptr, input_filter::cache_type> input_filter_cache_;

    std::unordered_set<rule::ptr> rules_to_exclude_;
    std::unordered_map<rule::ptr, object_set> objects_to_exclude_;

    // Cache of rules and conditions
    std::unordered_map<rule::ptr, rule::cache_type> rule_cache_;
    // Cache of collections to avoid processing once a result has been obtained
    std::unordered_set<std::string> collection_cache_;
};

} // namespace ddwaf
