// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <memory>

#include "context_allocator.hpp"

namespace ddwaf::memory {

namespace {
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
std::unique_ptr<null_memory_resource> global_memory_resource{new null_memory_resource};
} // namespace

// NOLINTNEXTLINE(misc-include-cleaner)
thread_local std::pmr::memory_resource *local_memory_resource{global_memory_resource.get()};

} // namespace ddwaf::memory
