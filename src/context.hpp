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
        const memory::memory_resource_guard guard(mr_.get());
        engine_.reset();
    }

    subcontext(subcontext &&) noexcept = delete;
    subcontext(const subcontext &) = delete;
    subcontext &operator=(subcontext &&) noexcept = delete;
    subcontext &operator=(const subcontext &) = delete;

    bool insert(owned_object data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(std::move(data));
    }

    bool insert(map_view data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(data);
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->eval(deadline);
    }

protected:
    explicit subcontext(evaluation_engine &ctx_engine)
        : mr_(std::make_shared<memory::monotonic_buffer_resource>())
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_ =
            std::make_unique<evaluation_engine>(evaluation_engine::subcontext_engine(ctx_engine));
    }

    std::unique_ptr<evaluation_engine> engine_;

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
        : mr_(std::make_shared<memory::monotonic_buffer_resource>())
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_ = std::make_unique<evaluation_engine>(
            evaluation_engine::context_engine(std::move(ruleset), output_alloc));
    }

    ~context()
    {
        const memory::memory_resource_guard guard(mr_.get());
        engine_.reset();
    }

    context(context &&) noexcept = delete;
    context(const context &) = delete;
    context &operator=(context &&) noexcept = delete;
    context &operator=(const context &) = delete;

    bool insert(owned_object data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(std::move(data));
    }

    bool insert(map_view data) noexcept
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->insert(data);
    }

    std::pair<bool, owned_object> eval(timer &deadline)
    {
        const memory::memory_resource_guard guard(mr_.get());
        return engine_->eval(deadline);
    }

    subcontext create_subcontext() { return subcontext{*engine_}; }

protected:
    std::unique_ptr<evaluation_engine> engine_;
    // This memory resource is primarily used for non-subcontext allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    std::shared_ptr<memory::monotonic_buffer_resource> mr_;
};

} // namespace ddwaf
