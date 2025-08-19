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

using filter_mode = exclusion::filter_mode;

class context {
public:
    using attribute = object_store::attribute;

    explicit context(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
        : engine_(std::move(ruleset), output_alloc)
    {}

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) = delete;
    context &operator=(context &&) = delete;
    ~context() = default;

    bool insert(owned_object data, attribute attr = attribute::none) noexcept
    {
        if (!store_.insert(std::move(data), attr)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    bool insert(map_view data, attribute attr = attribute::none) noexcept
    {
        if (!store_.insert(data, attr)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return false;
        }
        return true;
    }

    std::pair<bool, owned_object> eval(uint64_t timeout)
    {
        timer deadline{std::chrono::microseconds(timeout)};
        return engine_.eval(store_, deadline);
    }

protected:
    evaluation_engine engine_;
    object_store store_;
};

class context_wrapper {
public:
    explicit context_wrapper(std::shared_ptr<ruleset> ruleset,
        nonnull_ptr<memory::memory_resource> output_alloc = memory::get_default_resource())
    {
        memory::memory_resource_guard guard(&mr_);
        ctx_ = static_cast<context *>(mr_.allocate(sizeof(context), alignof(context)));
        new (ctx_) context{std::move(ruleset), output_alloc};
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

    bool insert(owned_object data, context::attribute attr = context::attribute::none) noexcept
    {
        memory::memory_resource_guard guard(&mr_);
        return ctx_->insert(std::move(data), attr);
    }

    bool insert(map_view data, context::attribute attr = context::attribute::none) noexcept
    {
        memory::memory_resource_guard guard(&mr_);
        return ctx_->insert(data, attr);
    }

    std::pair<bool, owned_object> eval(uint64_t timeout)
    {
        memory::memory_resource_guard guard(&mr_);
        return ctx_->eval(timeout);
    }

protected:
    context *ctx_;
    // This memory resource is primarily used for non-ephemeral allocations within the context
    // itself, such as for caching purposes of finite elements. This has the advantage of
    // improving the context destruction and memory deallocation performance.
    memory::monotonic_buffer_resource mr_;
};

} // namespace ddwaf
