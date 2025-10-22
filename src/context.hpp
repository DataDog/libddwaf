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
    ~subcontext()
    {
        {
            const memory::memory_resource_guard guard(mr_.get());
            engine_.reset();
            store_.reset();
        }

        {
            const memory::memory_resource_guard guard(ctx_mr_.get());
            ctx_store_.reset();
        }
    }

    subcontext(subcontext &&) noexcept = delete;
    subcontext(const subcontext &) = delete;
    subcontext &operator=(subcontext &&) noexcept = delete;
    subcontext &operator=(const subcontext &) = delete;

    bool insert(owned_object data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(std::move(data));
    }

    bool insert(map_view data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(data);
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->eval(deadline);
    }

    // Internals exposed for testing
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
    explicit subcontext(evaluation_engine &ctx_engine, std::shared_ptr<object_store> ctx_store,
        std::shared_ptr<memory::monotonic_buffer_resource> ctx_mr)
        : mr_(std::make_unique<memory::monotonic_buffer_resource>()),
          ctx_store_(std::move(ctx_store)), ctx_mr_(std::move(ctx_mr))
    {
        const memory::memory_resource_guard guard(mr_.get());
        store_ = std::make_unique<object_store>(object_store::from_upstream_store(*ctx_store_));
        engine_ = std::make_unique<evaluation_engine>(
            evaluation_engine::subcontext_engine(ctx_engine, *store_));
    }

    std::unique_ptr<object_store> store_;
    std::unique_ptr<evaluation_engine> engine_;

    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    std::unique_ptr<memory::monotonic_buffer_resource> mr_;

    // Shared context store to preserve the lifetime of user-provided objects, the
    // memory resource is required to be able to free the context store
    std::shared_ptr<object_store> ctx_store_;
    std::shared_ptr<memory::monotonic_buffer_resource> ctx_mr_;

    friend class context;
};

class context {
public:
    explicit context(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : mr_(std::make_shared<memory::monotonic_buffer_resource>())
    {
        const memory::memory_resource_guard guard(mr_.get());
        store_ = std::make_shared<object_store>();
        engine_ = std::make_unique<evaluation_engine>(
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

    bool insert(owned_object data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(std::move(data));
    }

    bool insert(map_view data)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(data);
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->eval(deadline);
    }

    subcontext create_subcontext() { return subcontext{*engine_, store_, mr_}; }

    // Internals exposed for testing
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

    std::unique_ptr<evaluation_engine> engine_;
    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    std::shared_ptr<memory::monotonic_buffer_resource> mr_;
};

} // namespace ddwaf
