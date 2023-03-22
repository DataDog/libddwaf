// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"

namespace ddwaf::memory {
thread_local std::pmr::memory_resource *local_memory_resource{std::pmr::null_memory_resource()};
} // namespace ddwaf::memory
