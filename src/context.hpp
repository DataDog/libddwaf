// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <optional>

#include <config.hpp>
#include <context_allocator.hpp>
#include <ddwaf.h>
#include <event.hpp>
#include <exclusion/input_filter.hpp>
#include <exclusion/rule_filter.hpp>
#include <obfuscator.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <utility>
#include <utils.hpp>

namespace ddwaf {

class context {
public:
    using object_set = std::unordered_set<const ddwaf_object *>;

    explicit context(std::shared_ptr<ruleset> ruleset)
        : ruleset_(std::move(ruleset)), store_(ruleset_->manifest, ruleset_->free_fn)
    {
        rule_filter_cache_.reserve(ruleset_->rule_filters.size());
        input_filter_cache_.reserve(ruleset_->input_filters.size());
        collection_cache_.reserve(ruleset_->collections.size());
    }

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) = default;
    context &operator=(context &&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(const ddwaf_object &, optional_ref<ddwaf_result> res, uint64_t);

    // These two functions below return references to internal objects,
    // however using them this way helps with testing
    const std::unordered_set<rule *> &filter_rules(ddwaf::timer &deadline);
    const std::unordered_map<rule *, object_set> &filter_inputs(
        const std::unordered_set<rule *> &rules_to_exclude, ddwaf::timer &deadline);

    std::vector<event> match(const std::unordered_set<rule *> &rules_to_exclude,
        const std::unordered_map<rule *, object_set> &objects_to_exclude, ddwaf::timer &deadline);

protected:
    bool is_first_run() const { return collection_cache_.empty(); }

    std::shared_ptr<ruleset> ruleset_;
    ddwaf::object_store store_;

    using input_filter = exclusion::input_filter;
    using rule_filter = exclusion::rule_filter;

    // Cache of filters and conditions
    memory::unordered_map<rule_filter *, rule_filter::cache_type> rule_filter_cache_;
    memory::unordered_map<input_filter *, input_filter::cache_type> input_filter_cache_;

    std::unordered_set<rule *> rules_to_exclude_;
    std::unordered_map<rule *, object_set> objects_to_exclude_;

    // Cache of collections to avoid processing once a result has been obtained
    memory::unordered_map<std::string_view, collection::cache_type> collection_cache_;
};

} // namespace ddwaf
