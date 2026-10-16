// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include "attribute_collector.hpp"
#include "cache_array.hpp"
#include "clock.hpp"
#include "context_allocator.hpp"
#include "exclusion/common.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "input_batch_queue.hpp"
#include "log.hpp"
#include "memory_resource.hpp"
#include "module.hpp"
#include "module_category.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "ruleset.hpp"

namespace ddwaf {

// The state of the evaluation of a context or subcontext, with one cache per
// processor, filter and rule, in ruleset order.
//
// The cache of a subcontext derives from that of its context: it reads the
// context's cache and only copies the entries it modifies, so that creating
// and destroying a subcontext doesn't depend on the size of the ruleset. The
// context's cache must therefore remain unchanged during the lifetime of its
// subcontexts, see evaluation_engine::make_cache_writable.
struct evaluation_cache {
    cache_array<processor_cache> preprocessors;
    cache_array<processor_cache> postprocessors;
    cache_array<rule_filter::cache_type> rule_filters;
    cache_array<input_filter::cache_type> input_filters;
    std::array<rule_module_cache, rule_module_count> rule_modules;

    exclusion_policy exclusions;

    // Initial cache of a context
    explicit evaluation_cache(const ruleset &rs);

    // Cache inheriting the state of the upstream one, i.e. that of a
    // subcontext over the cache of its context. The upstream cache must
    // neither be modified nor destroyed during the lifetime of the new one.
    static evaluation_cache derive(const evaluation_cache &upstream);

protected:
    evaluation_cache() = default;
};

class evaluation_engine {
public:
    evaluation_engine(const evaluation_engine &) = delete;
    evaluation_engine &operator=(const evaluation_engine &) = delete;
    evaluation_engine(evaluation_engine &&) = default;
    evaluation_engine &operator=(evaluation_engine &&) = delete;
    ~evaluation_engine() = default;

    bool insert_batch(owned_object data) noexcept
    {
        if (!input_batches_.insert_batch(store_, std::move(data))) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert_batch(map_view data) noexcept
    {
        if (!input_batches_.insert_batch(store_, data)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert_batches(owned_object data) noexcept
    {
        if (!input_batches_.insert_batches(store_, std::move(data))) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert_batches(array_view data) noexcept
    {
        if (!input_batches_.insert_batches(store_, data)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    // Internals exposed for testing
    bool next_batch() { return input_batches_.next_batch(store_); }
    bool insert_and_apply(owned_object data) noexcept
    {
        return store_.insert_and_apply(std::move(data));
    }
    bool insert_and_apply(map_view data) noexcept { return store_.insert_and_apply(data); }
    std::pair<bool, owned_object> eval(timer &deadline);

    // The cache, like the rest of the engine, is allocated with the memory
    // resource of the context or subcontext.
    static evaluation_engine context_engine(std::shared_ptr<ruleset> ruleset, object_store &store,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
    {
        auto cache = std::allocate_shared<evaluation_cache>(
            memory::context_allocator<evaluation_cache>{}, *ruleset);
        return evaluation_engine{std::move(ruleset), store, std::move(cache),
            attribute_collector{output_alloc}, output_alloc};
    }

    // The cache of the subcontext engine derives from the context cache, which
    // must have been obtained through share_cache and must be kept alive
    // during the lifetime of the subcontext engine.
    static evaluation_engine subcontext_engine(
        evaluation_engine &engine, object_store &store, const evaluation_cache &ctx_cache)
    {
        auto cache = std::allocate_shared<evaluation_cache>(
            memory::context_allocator<evaluation_cache>{}, evaluation_cache::derive(ctx_cache));
        return evaluation_engine{engine.ruleset_, store, std::move(cache),
            attribute_collector::from_upstream_collector(engine.collector_), engine.output_alloc_};
    }

    // Shares the cache, e.g. with a subcontext: while the returned pointer is
    // alive, the engine no longer modifies this cache but a copy of it. The
    // pointer must be released with the memory resource of this engine.
    [[nodiscard]] std::shared_ptr<const evaluation_cache> share_cache() const { return cache_; }

    // Internals exposed for testing
    void eval_preprocessors(timer &deadline);
    void eval_postprocessors(timer &deadline);
    // This function below returns a reference to an internal object,
    // however using them this way helps with testing
    exclusion_policy &eval_filters(timer &deadline);
    rule_verdict eval_rules(
        const exclusion_policy &policy, std::vector<rule_result> &results, timer &deadline);

protected:
    explicit evaluation_engine(std::shared_ptr<ruleset> ruleset, object_store &store,
        std::shared_ptr<evaluation_cache> cache, attribute_collector &&collector,
        nonnull_ptr<memory::memory_resource> output_alloc)
        : output_alloc_(output_alloc), ruleset_(std::move(ruleset)), store_(store),
          collector_(std::move(collector)), cache_(std::move(cache))
    {}

    // Replaces the cache with a copy if it's shared (see share_cache), so that
    // it can be modified. Must be called before modifying the cache.
    void make_cache_writable();

    // Flags as pending the rules referencing any of the targets updated since
    // the last call and returns whether any of those is a rule target new to
    // the current batch.
    bool flag_updated_rules();

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
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    object_store &store_;
    // Queue of pending input batches fed into the store during evaluation
    input_batch_queue input_batches_;
    attribute_collector collector_;

    // Caches, never null, see make_cache_writable
    std::shared_ptr<evaluation_cache> cache_;
};

} // namespace ddwaf
