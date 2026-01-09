// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "dynamic_string.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"

namespace ddwaf {

owned_object dynamic_string::to_object(nonnull_ptr<memory::memory_resource> alloc)
{
    const bool should_copy = size_ != capacity_ || !alloc->is_equal(*alloc_);
    owned_object object = should_copy ? owned_object::make_string(buffer_, size_, alloc)
                                      : // safety: the allocators compare equal; by definition
                                        // this means alloc (the deallocator for the owned_object)
                                        // can deallocate memory from alloc_ (the allocator for
                                        // this dynamic_string)
                              owned_object::make_string_nocopy(buffer_, size_, alloc);

    if (should_copy) {
        alloc_->deallocate(buffer_, capacity_, alignof(char));
    }
    buffer_ = nullptr;
    size_ = capacity_ = 0;
    return object;
}

} // namespace ddwaf
