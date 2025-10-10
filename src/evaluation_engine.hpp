// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <memory>

#include "attribute_collector.hpp"
#include "exclusion/common.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "memory_resource.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "ruleset.hpp"
#include "utils.hpp"

namespace ddwaf {

struct evaluation_cache {
    std::unordered_map<base_processor *, processor_cache> processor_;
    std::unordered_map<const rule_filter *, rule_filter::cache_type> rule_filter_;
    std::unordered_map<const input_filter *, input_filter::cache_type> input_filter_;
    std::array<rule_module_cache, rule_module_count> rule_module_;

    exclusion_policy exclusions_;
};

class evaluation_engine {
public:
    explicit evaluation_engine(std::shared_ptr<ruleset> ruleset, base_object_store &store,
        evaluation_scope scope, evaluation_cache &cache,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : scope_(scope), output_alloc_(output_alloc), ruleset_(std::move(ruleset)), store_(store),
          collector_(output_alloc), cache_(cache)
    {
        cache_.processor_.reserve(
            ruleset_->preprocessors->size() + ruleset_->postprocessors->size());
        cache.rule_filter_.reserve(ruleset_->rule_filters->size());
        cache.input_filter_.reserve(ruleset_->input_filters->size());

        for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
            ruleset_->rule_modules[i].init_cache(cache_.rule_module_[i]);
        }
    }

    evaluation_engine(const evaluation_engine &) = delete;
    evaluation_engine &operator=(const evaluation_engine &) = delete;
    evaluation_engine(evaluation_engine &&) = delete;
    evaluation_engine &operator=(evaluation_engine &&) = delete;
    ~evaluation_engine() = default;

    std::pair<bool, owned_object> eval(timer &deadline);

    // Internals exposed for testing
    void eval_preprocessors(timer &deadline);
    void eval_postprocessors(timer &deadline);
    // This function below returns a reference to an internal object,
    // however using them this way helps with testing
    exclusion_policy &eval_filters(timer &deadline);
    void eval_rules(
        const exclusion_policy &policy, std::vector<rule_result> &results, timer &deadline);

protected:
    bool check_new_rule_targets() const
    {
        // NOLINTNEXTLINE(readability-use-anyofallof)
        for (const auto &[target, str] : ruleset_->rule_addresses) {
            if (store_.is_new_target(target)) {
                return true;
            }
        }
        return false;
    }

    bool check_new_filter_targets() const
    {
        // NOLINTNEXTLINE(readability-use-anyofallof)
        for (const auto &[target, str] : ruleset_->filter_addresses) {
            if (store_.is_new_target(target)) {
                return true;
            }
        }
        return false;
    }

    // The current scope: context or subcontext
    evaluation_scope scope_;

    // This memory resource is used primarily for the allocation of memory
    // which will be returned to the user.
    nonnull_ptr<memory::memory_resource> output_alloc_;

    std::shared_ptr<ruleset> ruleset_;
    base_object_store &store_;
    attribute_collector collector_;

    evaluation_cache &cache_;
};

} // namespace ddwaf
