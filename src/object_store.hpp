// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <manifest.hpp>

namespace ddwaf
{

class object_store
{
public:
    explicit object_store(const manifest& m,
        ddwaf_object_free_fn free_fn = ddwaf_object_free);
    ~object_store();

    bool insert(const ddwaf_object &input);

    const ddwaf_object *get_target(const manifest::target_type target) const;

    bool is_new_target(const manifest::target_type target) const {
        return latest_batch_.find(manifest::get_root(target)) != latest_batch_.cend();
    }

    bool has_new_targets() const {
        return !latest_batch_.empty();
    }

    operator bool() const {
        return !objects_.empty();
    }

protected:
    const ddwaf::manifest& manifest_;

    std::unordered_set<manifest::target_type> latest_batch_;
    std::unordered_map<manifest::target_type, const ddwaf_object *> objects_;

    std::vector<ddwaf_object> objects_to_free_;
    ddwaf_object_free_fn obj_free_;
};

}
