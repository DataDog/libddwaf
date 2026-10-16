// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "arena_resource.hpp"
#include "clock.hpp"
#include "context_allocator.hpp"
#include "evaluation_engine.hpp"
#include "exclusion/common.hpp"
#include "internal_resource.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "pointer.hpp"
#include "rule.hpp"
#include "ruleset.hpp"

namespace ddwaf {

class context;

// Initial block sizes of the context and subcontext arenas; further blocks
// double in size (see memory::arena_resource). With the recommended ruleset, a
// context or a subcontext (which copies the evaluation caches of its context)
// typically uses between 32 and 64 KiB, so two blocks.
inline constexpr std::size_t context_arena_initial_size = 32768;
inline constexpr std::size_t subcontext_arena_initial_size = 32768;

class subcontext {
public:
    // Contexts and subcontexts are allocated by the interface (ddwaf_context_init
    // and ddwaf_subcontext_init) on every request; their memory comes from the
    // internal block cache rather than from the system allocator.
    static void *operator new(std::size_t size)
    {
        return memory::internal_block_cache::allocate(size);
    }
    static void operator delete(void *ptr, std::size_t size) noexcept
    {
        memory::internal_block_cache::deallocate(ptr, size);
    }

    ~subcontext()
    {
        {
            const memory::memory_resource_guard guard(&mr_);
            engine_.reset();
            store_.reset();
        }

        {
            const memory::memory_resource_guard guard(ctx_mr_.get());
            ctx_cache_.reset();
            ctx_store_.reset();
        }
    }

    subcontext(subcontext &&) noexcept = delete;
    subcontext(const subcontext &) = delete;
    subcontext &operator=(subcontext &&) noexcept = delete;
    subcontext &operator=(const subcontext &) = delete;

    bool insert_batch(owned_object data)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->insert_batch(std::move(data));
    }

    bool insert_batch(map_view data)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->insert_batch(data);
    }

    bool insert_batches(owned_object data)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->insert_batches(std::move(data));
    }

    bool insert_batches(array_view data)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->insert_batches(data);
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->eval(deadline);
    }

    // Internals exposed for testing
    bool next_batch()
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->next_batch();
    }
    bool insert_and_apply(owned_object data)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->insert_and_apply(std::move(data));
    }
    bool insert_and_apply(map_view data)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->insert_and_apply(data);
    }
    void eval_preprocessors(timer &deadline)
    {
        const memory::memory_resource_guard guard(&mr_);
        engine_->eval_preprocessors(deadline);
    }
    void eval_postprocessors(timer &deadline)
    {
        const memory::memory_resource_guard guard(&mr_);
        engine_->eval_postprocessors(deadline);
    }
    // This function below returns a reference to an internal object,
    // however using them this way helps with testing
    exclusion_policy &eval_filters(timer &deadline)
    {
        const memory::memory_resource_guard guard(&mr_);
        return engine_->eval_filters(deadline);
    }
    void eval_rules(
        const exclusion_policy &policy, std::vector<rule_result> &results, timer &deadline)
    {
        const memory::memory_resource_guard guard(&mr_);
        engine_->eval_rules(policy, results, deadline);
    }

protected:
    explicit subcontext(evaluation_engine &ctx_engine, std::shared_ptr<object_store> ctx_store,
        std::shared_ptr<memory::arena_resource> ctx_mr)
        : mr_(subcontext_arena_initial_size), ctx_store_(std::move(ctx_store)),
          ctx_cache_(ctx_engine.share_cache()),
          ctx_mr_(std::move(ctx_mr))
    {
        const memory::memory_resource_guard guard(&mr_);
        store_.emplace(object_store::from_upstream_store(*ctx_store_));
        engine_.emplace(evaluation_engine::subcontext_engine(ctx_engine, *store_, *ctx_cache_));
    }

    // Constructed in place to save two allocations per subcontext; destroyed
    // explicitly, with the arena installed, by the destructor.
    std::optional<object_store> store_;
    std::optional<evaluation_engine> engine_;

    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    memory::arena_resource mr_;

    // Shared context store to preserve the lifetime of user-provided objects, the
    // memory resource is required to be able to free the context store
    std::shared_ptr<object_store> ctx_store_;
    // Shared context cache, from which the cache of the subcontext derives,
    // released with the context's memory resource (see
    // evaluation_engine::share_cache)
    std::shared_ptr<const evaluation_cache> ctx_cache_;
    std::shared_ptr<memory::arena_resource> ctx_mr_;

    friend class context;
};

class context {
public:
    // See subcontext::operator new
    static void *operator new(std::size_t size)
    {
        return memory::internal_block_cache::allocate(size);
    }
    static void operator delete(void *ptr, std::size_t size) noexcept
    {
        memory::internal_block_cache::deallocate(ptr, size);
    }

    explicit context(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : mr_(std::allocate_shared<memory::arena_resource>(
              memory::internal_allocator<memory::arena_resource>{}, context_arena_initial_size))
    {
        const memory::memory_resource_guard guard(mr_.get());
        // Shared with the subcontexts, which may outlive the context. The
        // ruleset, and so its lookup, outlives the store, as it's kept alive
        // by the engine (of the context and of each subcontext).
        store_ = std::allocate_shared<object_store>(
            memory::internal_allocator<object_store>{}, ruleset->target_names.get());
        engine_.emplace(
            evaluation_engine::context_engine(std::move(ruleset), *store_, output_alloc));
    }

    ~context()
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_.reset();
        store_.reset();
    }

    context(context &&) noexcept = delete;
    context(const context &) = delete;
    context &operator=(context &&) noexcept = delete;
    context &operator=(const context &) = delete;

    bool insert_batch(owned_object data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert_batch(std::move(data));
    }

    bool insert_batch(map_view data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert_batch(data);
    }

    bool insert_batches(owned_object data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert_batches(std::move(data));
    }

    bool insert_batches(array_view data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert_batches(data);
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->eval(deadline);
    }

    subcontext create_subcontext() { return subcontext{*engine_, store_, mr_}; }

    // Internals exposed for testing
    [[nodiscard]] std::size_t arena_block_bytes() const { return mr_->block_bytes(); }
    bool next_batch()
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->next_batch();
    }
    bool insert_and_apply(owned_object data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert_and_apply(std::move(data));
    }
    bool insert_and_apply(map_view data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert_and_apply(data);
    }
    void eval_preprocessors(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_->eval_preprocessors(deadline);
    }
    void eval_postprocessors(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_->eval_postprocessors(deadline);
    }
    // This function below returns a reference to an internal object,
    // however using them this way helps with testing
    exclusion_policy &eval_filters(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->eval_filters(deadline);
    }
    void eval_rules(
        const exclusion_policy &policy, std::vector<rule_result> &results, timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_->eval_rules(policy, results, deadline);
    }

protected:
    std::shared_ptr<object_store> store_;

    std::optional<evaluation_engine> engine_;
    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    std::shared_ptr<memory::arena_resource> mr_;
};

} // namespace ddwaf
