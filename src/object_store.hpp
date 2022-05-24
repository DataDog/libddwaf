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
#include <PWManifest.h>

namespace ddwaf
{

class object_store
{
public:
    explicit object_store(const PWManifest& manifest): manifest_(manifest) {}

    void insert_object(const ddwaf_object &input);
    const ddwaf_object *get_object(const PWManifest::ARG_ID target) const;

    bool has_new_targets() const {
        return !latest_batch_.empty();
    }

    bool is_new_target(const PWManifest::ARG_ID target) const {
        return latest_batch_.find(target) != latest_batch_.cend();
    }

    operator bool() const {
        return !objects_.empty();
    }

protected:
    const PWManifest& manifest_;

    std::unordered_set<PWManifest::ARG_ID> latest_batch_;
    std::unordered_map<std::string, const ddwaf_object*> objects_;
};

}
