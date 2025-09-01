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
#include "obfuscator.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "ruleset.hpp"

namespace ddwaf {

class evaluation_engine {
public:
    explicit evaluation_engine(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : output_alloc_(output_alloc), ruleset_(std::move(ruleset)), collector_(output_alloc),
          preprocessors_(*ruleset_->preprocessors), postprocessors_(*ruleset_->postprocessors),
          rule_filters_(*ruleset_->rule_filters), input_filters_(*ruleset_->input_filters),
          rule_matchers_(*ruleset_->rule_matchers),
          exclusion_matchers_(*ruleset_->exclusion_matchers), actions_(*ruleset_->actions),
          obfuscator_(*ruleset_->obfuscator)
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

    bool insert(owned_object data, evaluation_scope scope = evaluation_scope::context) noexcept
    {
        if (!store_.insert(std::move(data), scope)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert(map_view data, evaluation_scope scope = evaluation_scope::context) noexcept
    {
        if (!store_.insert(data, scope)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    std::pair<bool, owned_object> eval(timer &deadline);

    void clear_subcontext_artifacts()
    {
        exclusions_.subcontext.clear();
        store_.clear_subcontext_objects();

        for (auto &cache : rule_module_cache_) { rule_module::invalidate_subcontext_cache(cache); }

        for (auto &[_, cache] : rule_filter_cache_) {
            exclusion::rule_filter::invalidate_subcontext_cache(cache);
        }

        for (auto &[_, cache] : input_filter_cache_) {
            exclusion::input_filter::invalidate_subcontext_cache(cache);
        }

        for (auto &[proc, cache] : processor_cache_) {
            base_processor::invalidate_subcontext_cache(cache);
        }
    }

    // Internals exposed for testing
    void eval_preprocessors(object_store &store, timer &deadline);
    void eval_postprocessors(object_store &store, timer &deadline);
    // This function below returns a reference to an internal object,
    // however using them this way helps with testing
    exclusion::exclusion_policy &eval_filters(object_store &store, timer &deadline);
    void eval_rules(object_store &store, const exclusion::exclusion_policy &policy,
        std::vector<rule_result> &results, timer &deadline);

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

    // This memory resource is used primarily for the allocation of memory
    // which will be returned to the user.
    nonnull_ptr<memory::memory_resource> output_alloc_;

    std::shared_ptr<ruleset> ruleset_;
    object_store store_;
    attribute_collector collector_;

    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    const std::vector<std::unique_ptr<base_processor>> &preprocessors_;
    const std::vector<std::unique_ptr<base_processor>> &postprocessors_;

    const std::vector<exclusion::rule_filter> &rule_filters_;
    const std::vector<exclusion::input_filter> &input_filters_;

    const matcher_mapper &rule_matchers_;
    const matcher_mapper &exclusion_matchers_;

    const action_mapper &actions_;

    const match_obfuscator &obfuscator_;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

    using input_filter = exclusion::input_filter;
    using rule_filter = exclusion::rule_filter;

    memory::unordered_map<base_processor *, processor_cache> processor_cache_;

    // Caches of filters and conditions
    memory::unordered_map<const rule_filter *, rule_filter::cache_type> rule_filter_cache_;
    memory::unordered_map<const input_filter *, input_filter::cache_type> input_filter_cache_;
    exclusion::exclusion_policy exclusions_;

    // Cache of modules to avoid processing once a result has been obtained
    std::array<rule_module_cache, rule_module_count> rule_module_cache_;
};

} // namespace ddwaf
