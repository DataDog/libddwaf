// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"

namespace ddwaf::memory {

namespace {
class null_memory_resource final : public std::pmr::memory_resource {
    void *do_allocate(size_t /*bytes*/, size_t /*alignment*/) override { throw std::bad_alloc(); }
    void do_deallocate(void * /*p*/, size_t /*bytes*/, size_t /*alignment*/) noexcept override {}
    [[nodiscard]] bool do_is_equal(const memory_resource &other) const noexcept override
    {
        return this == &other;
    }
};

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
null_memory_resource global_memory_resource;
} // namespace

thread_local std::pmr::memory_resource *local_memory_resource{&global_memory_resource};

} // namespace ddwaf::memory
