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
    memory::unordered_map<base_processor *, processor_cache> processors;
    memory::unordered_map<const rule_filter *, rule_filter::cache_type> rule_filters;
    memory::unordered_map<const input_filter *, input_filter::cache_type> input_filters;
    std::array<rule_module_cache, rule_module_count> rule_modules;

    exclusion_policy exclusions;
};

class evaluation_engine {
public:
    evaluation_engine(const evaluation_engine &) = delete;
    evaluation_engine &operator=(const evaluation_engine &) = delete;
    evaluation_engine(evaluation_engine &&) = default;
    evaluation_engine &operator=(evaluation_engine &&) = default;
    ~evaluation_engine() = default;

    bool insert(owned_object data) noexcept
    {
        if (!store_.insert(std::move(data))) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert(map_view data) noexcept
    {
        if (!store_.insert(data)) {
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

    static evaluation_engine context_engine(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
    {
        return evaluation_engine{std::move(ruleset), object_store::make_context_store(),
            evaluation_scope::context(), evaluation_cache{}, output_alloc};
    }

    static evaluation_engine subcontext_engine(evaluation_engine &engine)
    {
        return evaluation_engine{engine.ruleset_,
            object_store::make_subcontext_store(engine.store_), evaluation_scope::subcontext(),
            engine.cache_, engine.output_alloc_};
    }

protected:
    explicit evaluation_engine(std::shared_ptr<ruleset> ruleset, object_store &&store,
        evaluation_scope scope, evaluation_cache cache,
        nonnull_ptr<memory::memory_resource> output_alloc)
        : scope_(scope), output_alloc_(output_alloc), ruleset_(std::move(ruleset)),
          store_(std::move(store)), collector_(output_alloc), cache_(std::move(cache))
    {
        cache_.processors.reserve(
            ruleset_->preprocessors->size() + ruleset_->postprocessors->size());
        cache.rule_filters.reserve(ruleset_->rule_filters->size());
        cache.input_filters.reserve(ruleset_->input_filters->size());

        for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
            ruleset_->rule_modules[i].init_cache(cache_.rule_modules[i]);
        }
    }

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
    object_store store_;
    attribute_collector collector_;

    // Caches
    evaluation_cache cache_;
};

} // namespace ddwaf
