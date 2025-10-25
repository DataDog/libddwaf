// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

#include <cstddef>
#include <new>
#include <version>

#if defined(__cpp_lib_memory_resource)
#  include <memory_resource>
#else
#  include <experimental/memory_resource>
#  include <string>
#  include <unordered_map>
#  include <unordered_set>
#  include <vector>

#  if !defined(__cpp_lib_experimental_memory_resources)
#    include "libcxx-compat/monotonic_buffer_resource.hpp"
#    include "libcxx-compat/synchronized_pool_resource.hpp"
#    include "libcxx-compat/unsynchronized_pool_resource.hpp"

namespace std { // NOLINT(cert-dcl58-cpp)
namespace pmr = std::experimental::pmr;
} // namespace std

#  endif
#endif

namespace ddwaf::memory {

using memory_resource = std::pmr::memory_resource;
using monotonic_buffer_resource = std::pmr::monotonic_buffer_resource;
using unsynchronized_pool_resource = std::pmr::unsynchronized_pool_resource;
using synchronized_pool_resource = std::pmr::synchronized_pool_resource;

const auto get_default_resource = std::pmr::get_default_resource;
const auto set_default_resource = std::pmr::set_default_resource;

// The null memory resource is used as the default onef or the static thread
// local memory resource. Only exposed for testing purposes.
class null_memory_resource final : public memory_resource {
    void *do_allocate(size_t /*bytes*/, size_t /*alignment*/) override { throw std::bad_alloc(); }
    void do_deallocate(void * /*p*/, size_t /*bytes*/, size_t /*alignment*/) noexcept override {}
    [[nodiscard]] bool do_is_equal(const memory_resource &other) const noexcept override
    {
        return this == &other;
    }
};

inline memory_resource *get_default_null_resource()
{
    static null_memory_resource resource;
    return &resource;
}

} // namespace ddwaf::memory
