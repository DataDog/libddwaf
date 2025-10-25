// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <string_view>

#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"

namespace ddwaf {

owned_object json_to_object(std::string_view json,
    nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource());

} // namespace ddwaf
