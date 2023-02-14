// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <iostream>
#include <manifest.hpp>

namespace ddwaf {
manifest::target_type manifest::insert(const std::string &root)
{
    auto it = targets_.find(root);
    if (it == targets_.end()) {
        auto [new_it, res] = targets_.emplace(root, ++index_);
        it = new_it;
    }
    return it->second;
}

std::optional<manifest::target_type> manifest::find(const std::string &root) const
{
    auto it = targets_.find(root);
    if (it == targets_.end()) {
        return std::nullopt;
    }
    return {it->second};
}

void manifest::remove_unused(const std::unordered_set<target_type> &valid_targets)
{
    for (auto it = targets_.begin(); it != targets_.end();) {
        if (valid_targets.find(it->second) == valid_targets.end()) {
            it = targets_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace ddwaf
