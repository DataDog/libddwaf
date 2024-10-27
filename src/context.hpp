// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <optional>
#include <utility>

#include "context_allocator.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "module.hpp"
#include "obfuscator.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "utils.hpp"

namespace ddwaf {

using filter_mode = exclusion::filter_mode;

class context {
public:
    using object_set = std::unordered_set<const ddwaf_object *>;

    explicit context(std::shared_ptr<ruleset> ruleset) : ruleset_(std::move(ruleset))
    {
        rule_filter_cache_.reserve(ruleset_->rule_filters.size());
        input_filter_cache_.reserve(ruleset_->input_filters.size());
        ruleset_->rules.init_cache(collection_cache_);
    }

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) = default;
    context &operator=(context &&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(optional_ref<ddwaf_object>, optional_ref<ddwaf_object>,
        optional_ref<ddwaf_result>, uint64_t);

    void eval_preprocessors(optional_ref<ddwaf_object> &derived, ddwaf::timer &deadline);
    void eval_postprocessors(optional_ref<ddwaf_object> &derived, ddwaf::timer &deadline);
    // This function below returns a reference to an internal object,
    // however using them this way helps with testing
    exclusion::context_policy &eval_filters(ddwaf::timer &deadline);
    std::vector<event> eval_rules(const exclusion::context_policy &policy, ddwaf::timer &deadline);

protected:
    bool is_first_run() const { return collection_cache_.empty(); }
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
    std::shared_ptr<ruleset> ruleset_;
    ddwaf::object_store store_;

    using input_filter = exclusion::input_filter;
    using rule_filter = exclusion::rule_filter;

    memory::unordered_map<base_processor *, processor_cache> processor_cache_;

    // Caches of filters and conditions
    memory::unordered_map<rule_filter *, rule_filter::cache_type> rule_filter_cache_;
    memory::unordered_map<input_filter *, input_filter::cache_type> input_filter_cache_;
    exclusion::context_policy exclusion_policy_;

    // Cache of collections to avoid processing once a result has been obtained
    collection_module::cache_type collection_cache_{};
};

class context_wrapper {
public:
    explicit context_wrapper(std::shared_ptr<ruleset> ruleset)
    {
        memory::memory_resource_guard guard(&mr_);
        ctx_ = static_cast<context *>(mr_.allocate(sizeof(context), alignof(context)));
        new (ctx_) context{std::move(ruleset)};
    }

    ~context_wrapper()
    {
        memory::memory_resource_guard guard(&mr_);
        ctx_->~context();
        mr_.deallocate(static_cast<void *>(ctx_), sizeof(context), alignof(context));
    }

    context_wrapper(context_wrapper &&) noexcept = delete;
    context_wrapper(const context_wrapper &) = delete;
    context_wrapper &operator=(context_wrapper &&) noexcept = delete;
    context_wrapper &operator=(const context_wrapper &) = delete;

    DDWAF_RET_CODE run(optional_ref<ddwaf_object> persistent, optional_ref<ddwaf_object> ephemeral,
        optional_ref<ddwaf_result> res, uint64_t timeout)
    {
        memory::memory_resource_guard guard(&mr_);
        return ctx_->run(persistent, ephemeral, res, timeout);
    }

protected:
    context *ctx_;
    std::pmr::monotonic_buffer_resource mr_;
};

} // namespace ddwaf
