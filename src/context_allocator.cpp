// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"
#include "memory_resource.hpp"

namespace ddwaf::memory {

namespace {
// The default thread local resource: a null resource distinct from
// get_default_null_resource(), constant-initialised so that the thread local
// pointer below needs no dynamic initialisation either.
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
constinit null_memory_resource local_null_resource{};
} // namespace

// NOLINTNEXTLINE(misc-include-cleaner)
constinit thread_local memory_resource *local_memory_resource{&local_null_resource};

} // namespace ddwaf::memory
