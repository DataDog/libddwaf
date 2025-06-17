// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

#include <version>
#include <stdexcept>

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
#  endif

#endif

namespace ddwaf::memory {

using memory_resource = std::pmr::memory_resource;
using monotonic_buffer_resource = std::pmr::monotonic_buffer_resource;

const auto get_default_resource = std::pmr::get_default_resource;

class user_resource : public memory_resource {
public:
    using alloc_fn_type = void *(*)(void *, size_t size, size_t alignment);
    using free_fn_type = void (*)(void *, void *, size_t size, size_t alignment);

    user_resource(void *data, alloc_fn_type alloc_fn, free_fn_type free_fn)
        : data_(data), alloc_fn_(alloc_fn), free_fn_(free_fn)
    {
        if (alloc_fn_ == nullptr || free_fn_ == nullptr) {
            throw std::invalid_argument("undefined user alloc/free function");
        }
    }

private:
    void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        return alloc_fn_(data_, bytes, alignment);
    }

    void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override
    {
        free_fn_(data_, p, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
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

    void *data_;
    alloc_fn_type alloc_fn_;
    free_fn_type free_fn_;
};

} // namespace ddwaf::memory
