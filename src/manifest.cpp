// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <iostream>
#include <manifest.hpp>

namespace ddwaf
{
manifest::target_type manifest::insert(const std::string &name,
    const std::string &root, const std::string &key_path)
{
    target_type root_target;
    auto root_it = targets_.find(root);
    if (root_it == targets_.end()) {
        // The root target doesn't exist, add it!
        root_target = target_counter_++;

        targets_.emplace(root, root_target);
        info_.emplace(root_target, target_info{root_target, {}});
        derived_.emplace(root_target, target_set{});
        root_address_set_.emplace(root);
        names_.emplace(root_target, root);
    } else {
        root_target = root_it->second;
    }

    // Targets with key path should have a different name than the root
    if (name == root) {
        derived_[root_target].emplace(root_target);
        return root_target;
    }

    // The target already exists, return that target
    auto current_it = targets_.find(name);
    if (current_it != targets_.end()) { return current_it->second; }

    target_info info;
    info.first = root_target;
    if (!key_path.empty()) {
        info.second.push_back(key_path);
    }
    // Not already in the manifest
    target_type current_target = target_counter_++;
    targets_.emplace(name, current_target);
    info_.emplace(current_target, std::move(info));
    derived_[root_target].emplace(current_target);
    names_.emplace(current_target, name);

    return current_target;
}

bool manifest::contains(const std::string& name) const
{
    return targets_.find(name) != targets_.end();
}

manifest::target_type manifest::get_target(const std::string& name) const
{
    auto it = targets_.find(name);
    if (it == targets_.end()) {
        return {};
    }
    return it->second;
}

std::string manifest::get_target_name(manifest::target_type target) const
{
    auto it = names_.find(target);
    if (it == names_.end()) {
        return {};
    }
    return it->second;
}

const manifest::target_info manifest::get_target_info(manifest::target_type target) const
{
    auto it = info_.find(target);
    if (it == info_.end()) {
        return {};
    }
    return it->second;
}

void manifest::find_derived_targets(const target_set& root_targets,
    target_set& derived_targets) const
{
    for (auto target : root_targets) {
        auto it = derived_.find(target);
        if (it != derived_.end()) {
            derived_targets.insert(it->second.begin(), it->second.end());
        }
    }
}


const std::vector<const char*>& manifest::get_root_addresses()
{
    if (root_addresses_.empty()) {
        root_addresses_.reserve(root_address_set_.size());
        for (const auto &address : root_address_set_) {
            root_addresses_.push_back(address.c_str());
        }
    }
    return root_addresses_;
}
}
