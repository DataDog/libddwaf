// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <utility>

#include "context_allocator.hpp"
#include "evaluation_engine.hpp"
#include "memory_resource.hpp"
#include "pointer.hpp"
#include "ruleset.hpp"

namespace ddwaf {

class context;

class subcontext {
public:
    ~subcontext() = default;

    subcontext(subcontext &&) noexcept = delete;
    subcontext(const subcontext &) = delete;
    subcontext &operator=(subcontext &&) noexcept = delete;
    subcontext &operator=(const subcontext &) = delete;

    bool insert(owned_object data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        if (!internal_->store.insert(std::move(data))) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert(map_view data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        if (!internal_->store.insert(data)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return internal_->engine.eval(deadline);
    }

protected:
    explicit subcontext(std::shared_ptr<ruleset> ruleset, evaluation_scope scope,
        const object_store &store, const evaluation_cache &cache,
        nonnull_ptr<memory::memory_resource> output_alloc,
        std::shared_ptr<memory::monotonic_buffer_resource> mr)
        : mr_(std::move(mr))
    {
        const memory::memory_resource_guard guard(mr_.get());
        internal_ = std::make_unique<subcontext_internals>(
            std::move(ruleset), scope, store, cache, output_alloc);
    }

    struct subcontext_internals {
        subcontext_object_store store;
        evaluation_cache cache;
        evaluation_engine engine;

        subcontext_internals(std::shared_ptr<ruleset> ruleset, evaluation_scope scope,
            const object_store &upstream_store, evaluation_cache upstream_cache,
            nonnull_ptr<memory::memory_resource> output_alloc)
            : store(upstream_store, scope), cache(std::move(upstream_cache)),
              engine(std::move(ruleset), store, scope, cache, output_alloc)
        {}
    };

    std::unique_ptr<subcontext_internals> internal_;

    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    std::shared_ptr<memory::monotonic_buffer_resource> mr_;

    friend class context;
};

class context {
public:
    explicit context(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : mr_(std::make_shared<memory::monotonic_buffer_resource>()), ruleset_(ruleset),
          output_alloc_(output_alloc)
    {
        const memory::memory_resource_guard guard(mr_.get());
        internal_ = std::make_unique<context_internals>(std::move(ruleset), output_alloc);
    }

    ~context()
    {
        const memory::memory_resource_guard guard(mr_.get());
        internal_.reset();
    }

    context(context &&) noexcept = delete;
    context(const context &) = delete;
    context &operator=(context &&) noexcept = delete;
    context &operator=(const context &) = delete;

    bool insert(owned_object data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        if (!internal_->store.insert(std::move(data))) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert(map_view data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        if (!internal_->store.insert(data)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return internal_->engine.eval(deadline);
    }

    subcontext create_subcontext()
    {
        return subcontext{ruleset_, evaluation_scope::next_subcontext(subcontext_scope_),
            internal_->store, internal_->cache, output_alloc_, mr_};
    }

protected:
    struct context_internals {
        object_store store;
        evaluation_cache cache;
        evaluation_engine engine;

        context_internals(
            std::shared_ptr<ruleset> ruleset, nonnull_ptr<memory::memory_resource> output_alloc)
            : engine(std::move(ruleset), store, evaluation_scope::context(), cache, output_alloc)
        {}
    };

    std::unique_ptr<context_internals> internal_;
    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    std::shared_ptr<memory::monotonic_buffer_resource> mr_;

    std::shared_ptr<ruleset> ruleset_;
    evaluation_scope subcontext_scope_;
    nonnull_ptr<memory::memory_resource> output_alloc_;
};

} // namespace ddwaf
