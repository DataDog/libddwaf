// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

#include <experimental/memory_resource>
#include <mutex>

#include "libcxx-compat/pool_options.hpp"
#include "libcxx-compat/unsynchronized_pool_resource.hpp"

namespace std::experimental::pmr { // NOLINT(cert-dcl58-cpp)

class synchronized_pool_resource : public memory_resource {
public:
    synchronized_pool_resource(const pool_options &__opts, memory_resource *__upstream)
        : __unsync_(__opts, __upstream)
    {}

    synchronized_pool_resource()
        : synchronized_pool_resource(pool_options(), get_default_resource())
    {}

    explicit synchronized_pool_resource(memory_resource *__upstream)
        : synchronized_pool_resource(pool_options(), __upstream)
    {}

    explicit synchronized_pool_resource(const pool_options &__opts)
        : synchronized_pool_resource(__opts, get_default_resource())
    {}

    synchronized_pool_resource(const synchronized_pool_resource &) = delete;

    ~synchronized_pool_resource() override = default;

    synchronized_pool_resource &operator=(const synchronized_pool_resource &) = delete;

    void release()
    {
        unique_lock<mutex> __lk(__mut_);
        __unsync_.release();
    }

    memory_resource *upstream_resource() const { return __unsync_.upstream_resource(); }

    pool_options options() const { return __unsync_.options(); }

protected:
    void *do_allocate(size_t __bytes, size_t __align) override
    {
        unique_lock<mutex> __lk(__mut_);
        return __unsync_.allocate(__bytes, __align);
    }

    void do_deallocate(void *__p, size_t __bytes, size_t __align) override
    {
        unique_lock<mutex> __lk(__mut_);
        return __unsync_.deallocate(__p, __bytes, __align);
    }

    bool do_is_equal(const memory_resource &__other) const noexcept override; // key function

private:
    mutex __mut_;
    unsynchronized_pool_resource __unsync_;
};

} // namespace std::experimental::pmr
