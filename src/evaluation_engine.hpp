// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <memory>

#include "attribute_collector.hpp"
#include "context_allocator.hpp"
#include "exclusion/common.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "memory_resource.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "ruleset.hpp"
#include "utils.hpp"

namespace ddwaf {

class evaluation_engine {
public:
    explicit evaluation_engine(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : output_alloc_(output_alloc), ruleset_(std::move(ruleset)), collector_(output_alloc)
    {
        processor_cache_.reserve(
            ruleset_->preprocessors->size() + ruleset_->postprocessors->size());
        rule_filter_cache_.reserve(ruleset_->rule_filters->size());
        input_filter_cache_.reserve(ruleset_->input_filters->size());

        for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
            ruleset_->rule_modules[i].init_cache(rule_module_cache_[i]);
        }
    }

    evaluation_engine(const evaluation_engine &) = delete;
    evaluation_engine &operator=(const evaluation_engine &) = delete;
    evaluation_engine(evaluation_engine &&) = delete;
    evaluation_engine &operator=(evaluation_engine &&) = delete;
    ~evaluation_engine() = default;

    void start_subcontext()
    {
        if (current_scope_.is_subcontext()) {
            throw std::runtime_error("subcontext already started");
        }

        subcontext_scope_ = evaluation_scope::next_subcontext(subcontext_scope_);
        current_scope_ = subcontext_scope_;
    }

    void stop_subcontext()
    {
        if (!current_scope_.is_subcontext()) {
            return;
        }

        exclusions_.subcontext.clear();
        store_.clear_subcontext_objects();

        current_scope_ = evaluation_scope::context();
    }

    bool in_subcontext() { return current_scope_.is_subcontext(); }

    bool insert(owned_object data) noexcept
    {
        if (!store_.insert(std::move(data), current_scope_)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert(map_view data) noexcept
    {
        if (!store_.insert(data, current_scope_)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

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

    // TODO Create a subcontext scope tracker instead of this
    evaluation_scope subcontext_scope_{evaluation_scope::subcontext()};

    // The current scope: context or subcontext
    evaluation_scope current_scope_;

    // This memory resource is used primarily for the allocation of memory
    // which will be returned to the user.
    nonnull_ptr<memory::memory_resource> output_alloc_;

    std::shared_ptr<ruleset> ruleset_;
    object_store store_;
    attribute_collector collector_;

    // Caches
    memory::unordered_map<base_processor *, processor_cache> processor_cache_;

    memory::unordered_map<const rule_filter *, rule_filter::cache_type> rule_filter_cache_;
    memory::unordered_map<const input_filter *, input_filter::cache_type> input_filter_cache_;
    exclusion_policy exclusions_;

    std::array<rule_module_cache, rule_module_count> rule_module_cache_;
};

} // namespace ddwaf
