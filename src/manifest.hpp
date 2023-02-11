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

class manifest {
public:
    using target_type = uint32_t;
    manifest::target_type insert(const std::string &root);
    std::optional<target_type> find(const std::string &root) const;

    // Remove unused targets
    void update_targets(const std::unordered_set<target_type> &valid_targets);

    // TODO root address generation
    const std::vector<const char *> &get_root_addresses() const { return root_addresses_; }
protected:
    std::unordered_map<std::string, target_type> targets_;
    target_type index_{0};

    // Root address memory to be returned to the API caller
    std::vector<const char *> root_addresses_;
};

} // namespace ddwaf
