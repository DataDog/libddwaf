// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

#include <experimental/memory_resource>

#include "libcxx-compat/pool_options.hpp"

namespace std::experimental::pmr { // NOLINT(cert-dcl58-cpp)

class unsynchronized_pool_resource : public memory_resource {
    class __fixed_pool;

    class __adhoc_pool {
        struct __chunk_footer;
        __chunk_footer *__first_;

    public:
        explicit __adhoc_pool() : __first_(nullptr) {}

        void __release_ptr(memory_resource *__upstream);
        void *__do_allocate(memory_resource *__upstream, size_t __bytes, size_t __align);
        void __do_deallocate(
            memory_resource *__upstream, void *__p, size_t __bytes, size_t __align);
    };

    static const size_t __min_blocks_per_chunk = 16;
    static const size_t __min_bytes_per_chunk = 1024;
    static const size_t __max_blocks_per_chunk = (size_t(1) << 20);
    static const size_t __max_bytes_per_chunk = (size_t(1) << 30);

    static const int __log2_smallest_block_size = 3;
    static const size_t __smallest_block_size = 8;
    static const size_t __default_largest_block_size = (size_t(1) << 20);
    static const size_t __max_largest_block_size = (size_t(1) << 30);

    size_t __pool_block_size(int __i) const;
    int __log2_pool_block_size(int __i) const;
    int __pool_index(size_t __bytes, size_t __align) const;

public:
    unsynchronized_pool_resource(const pool_options &__opts, memory_resource *__upstream);

    unsynchronized_pool_resource()
        : unsynchronized_pool_resource(pool_options(), get_default_resource())
    {}

    explicit unsynchronized_pool_resource(memory_resource *__upstream)
        : unsynchronized_pool_resource(pool_options(), __upstream)
    {}

    explicit unsynchronized_pool_resource(const pool_options &__opts)
        : unsynchronized_pool_resource(__opts, get_default_resource())
    {}

    unsynchronized_pool_resource(const unsynchronized_pool_resource &) = delete;

    ~unsynchronized_pool_resource() override { release(); }

    unsynchronized_pool_resource &operator=(const unsynchronized_pool_resource &) = delete;

    void release();

    memory_resource *upstream_resource() const { return __res_; }

    [[gnu::pure]] pool_options options() const;

protected:
    void *do_allocate(size_t __bytes, size_t __align) override; // key function

    void do_deallocate(void *__p, size_t __bytes, size_t __align) override;

    bool do_is_equal(const memory_resource &__other) const noexcept override
    {
        return &__other == this;
    }

private:
    memory_resource *__res_;
    __adhoc_pool __adhoc_pool_;
    __fixed_pool *__fixed_pools_;
    int __num_fixed_pools_;
    uint32_t __options_max_blocks_per_chunk_;
};

} // namespace std::experimental::pmr
