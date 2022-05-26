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
#include <utils.h>
#include <vector>

#include <ddwaf.h>

namespace ddwaf
{
class manifest
{
public:
    using target_type = uint32_t;
    using target_set = std::unordered_set<target_type>;
    struct target_info {
        std::string name;
        target_type root;
        std::vector<std::string> key_path;
    };

    manifest() = default;
    manifest(manifest&&)      = default;
    manifest(const manifest&) = delete;
    manifest& operator=(manifest&&) = default;
    manifest& operator=(const manifest&) = delete;

    target_type insert(const std::string &name, const std::string &root,
            const std::string &key_path = {});

    bool empty() { return targets_.empty(); }

    bool contains(const std::string& name) const;
    target_type get_target(const std::string& name) const;
    std::string get_target_name(target_type target) const;
    const target_info get_target_info(target_type target) const;

    void find_derived_targets(const target_set& root_targets,
            target_set& derived_targets) const;

    const std::vector<const char*>& get_root_addresses();

protected:

    std::unordered_map<std::string, target_type> targets_{};
    std::unordered_map<target_type, target_info> info_{};
    std::unordered_map<target_type, std::unordered_set<target_type>> derived_{};

    // Unique set of root addresses
    std::unordered_set<std::string> root_address_set_{};
    // Root address memory to be returned to the API caller
    std::vector<const char*> root_addresses_;

    target_type target_counter_{1};
};

}

