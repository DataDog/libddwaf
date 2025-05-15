// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "dynamic_string.hpp"
#include "object.hpp"

namespace ddwaf {

owned_object dynamic_string::to_object()
{
    auto final_size = size_;
    size_ = capacity_ = 0;
    return owned_object::make_string_nocopy(buffer_.release(), final_size);
}

} // namespace ddwaf
