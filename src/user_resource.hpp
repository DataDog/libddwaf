// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include "memory_resource.hpp"

namespace ddwaf::memory {

class user_resource : public memory::memory_resource {
public:
    using alloc_fn_type = void *(*)(void *, size_t, size_t);
    using free_fn_type = void (*)(void *, void *, size_t, size_t);
    using udata_free_fn_type = void (*)(void *);

    user_resource(
        alloc_fn_type alloc_fn, free_fn_type free_fn, void *udata, udata_free_fn_type udata_free_fn)
        : alloc_fn_(alloc_fn), free_fn_(free_fn), udata_(udata), udata_free_fn_(udata_free_fn)
    {
        if (alloc_fn_ == nullptr || free_fn_ == nullptr) {
            throw std::invalid_argument("undefined user alloc/free function");
        }
    }

    ~user_resource() override
    {
        if (udata_free_fn_ != nullptr) {
            udata_free_fn_(udata_);
        }
    }

private:
    void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        return alloc_fn_(udata_, bytes, alignment);
    }

    void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override
    {
        free_fn_(udata_, p, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const memory::memory_resource &other) const noexcept override
    {
        // Two memory_resources compare equal if and only if memory allocated from one
        //  memory_resource can be deallocated from the other and vice versa.
        try {
            const auto &user_mr = dynamic_cast<const user_resource &>(other);
            return free_fn_ == user_mr.free_fn_;
        } catch (const std::bad_cast &) {
            return false;
        }
    }

    alloc_fn_type alloc_fn_;
    free_fn_type free_fn_;
    void *udata_;
    udata_free_fn_type udata_free_fn_;
};

} // namespace ddwaf::memory
