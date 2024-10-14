// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#pragma once

#include <version>

#if defined(__cpp_lib_memory_resource) || defined(HAS_MEMORY_RESOURCE)
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
