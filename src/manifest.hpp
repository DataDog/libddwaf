// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <utils.hpp>
#include <vector>

#include <ddwaf.h>

namespace ddwaf {

// TODO bring back manifest builder?
class manifest {
public:
    using target_type = uint32_t;
    manifest::target_type insert(const std::string &root);
    std::optional<target_type> find(const std::string &root) const;

    // Remove unused targets
    void update_targets(const std::unordered_set<target_type> &valid_targets);

    // TODO This is problematic because if the manifest is modified after the
    //      first call to this function, the array will be out-of-sync. At the
    //      same time we can't invalidate it.
    //      This is not really a problem in practice since each ruleset has its
    //      own manifest copy, but it would be better to avoid an inconsistent
    //      interface that could be misused.
    const std::vector<const char *> &get_root_addresses() {
        if (root_addresses_.empty()) {
            for (const auto &[id, target] : targets_) {
                root_addresses_.emplace_back(id.c_str());
            }
        }
        return root_addresses_;
    }

protected:
    std::unordered_map<std::string, target_type> targets_;
    target_type index_{0};

    // Root address memory to be returned to the API caller
    std::vector<const char *> root_addresses_;
};

} // namespace ddwaf
