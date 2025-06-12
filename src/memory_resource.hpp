// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

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
#  endif

#endif

namespace ddwaf::memory {

using memory_resource = std::pmr::memory_resource;
using monotonic_buffer_resource = std::pmr::monotonic_buffer_resource;

const auto get_default_resource = std::pmr::get_default_resource;

} // namespace ddwaf::memory
