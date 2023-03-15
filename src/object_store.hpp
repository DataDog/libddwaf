// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <manifest.hpp>
#include <memory_resource>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace ddwaf {

class object_store {
public:
    // we don't use it in standard containers; no need to define allocator_type
    // and corresponding constructors
    using alloc_type = std::pmr::polymorphic_allocator<std::byte>;

    explicit object_store(
        const manifest &m, ddwaf_object_free_fn free_fn = ddwaf_object_free, alloc_type alloc = {});
    object_store(const manifest &m, alloc_type alloc);
    object_store(const object_store &) = default;
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &) = delete;
    object_store &operator=(object_store &&) = delete;
    ~object_store();

    bool insert(const ddwaf_object &input);

    const ddwaf_object *get_target(manifest::target_type target) const;

    bool is_new_target(const manifest::target_type target) const
    {
        return latest_batch_.find(target) != latest_batch_.cend();
    }

    bool has_new_targets() const { return !latest_batch_.empty(); }

    explicit operator bool() const { return !objects_.empty(); }

protected:
    const ddwaf::manifest &manifest_;

    std::pmr::unordered_set<manifest::target_type> latest_batch_;
    std::pmr::unordered_map<manifest::target_type, const ddwaf_object *> objects_;

    std::pmr::vector<ddwaf_object> objects_to_free_;
    ddwaf_object_free_fn obj_free_;
};

} // namespace ddwaf
