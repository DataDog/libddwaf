// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "context_allocator.hpp"
#include "ddwaf.h"

namespace ddwaf::exclusion {

struct object_set {
    memory::unordered_set<const ddwaf_object *> persistent;
    memory::unordered_set<const ddwaf_object *> ephemeral;

    bool empty() const { return persistent.empty() && ephemeral.empty(); }
    std::size_t size() const { return persistent.size() + ephemeral.size(); }
    void copy_from(const object_set &objects)
    {
        persistent.insert(objects.persistent.begin(), objects.persistent.end());
        ephemeral.insert(objects.ephemeral.begin(), objects.ephemeral.end());
    }
    bool contains(const ddwaf_object *obj) const
    {
        return persistent.contains(obj) || ephemeral.contains(obj);
    }
};

} // namespace ddwaf::exclusion
