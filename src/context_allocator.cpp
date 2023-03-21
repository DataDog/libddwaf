// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"
#include <memory_resource>
namespace ddwaf::memory {
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
std::pmr::memory_resource *global_memory_resource{std::pmr::new_delete_resource()};
thread_local std::pmr::memory_resource *local_memory_resource{global_memory_resource};

} // namespace ddwaf::memory
