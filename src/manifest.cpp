// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <iostream>
#include <manifest.hpp>

namespace ddwaf
{

manifest::target_type manifest_builder::insert(const std::string& root,
    const std::vector<std::string>& key_path)
{
    auto it = targets_.find(root);
    if (it == targets_.end()) {
        index_++;
        auto [new_it, res] = targets_.emplace(root, target_spec{index_, 0, {}});
        // assume res = true
        it = new_it;
    }

    auto &[root_id, derived_id, derived_map] = it->second;

    if (key_path.empty()) {
        return {root_id, 0};
    }

    auto derived_it = derived_map.find(key_path);
    if (derived_it == derived_map.end()) {
        auto [new_it, res] = derived_map.emplace(key_path, ++derived_id);
        derived_it = new_it;
    }

    return {root_id, derived_it->second};
}

manifest manifest_builder::build_manifest() {
    std::unordered_map<std::string, manifest::target_type> targets;
    manifest::target_type::map<manifest::target_info> info;

    for (auto &[key, spec] : targets_) {
        manifest::target_type root(spec.root_id, 0);

        targets.emplace(key, root);
        info.emplace(root, manifest::target_info{key, {}});

        for (auto &[key_path, derived_id] : spec.derived) {
            manifest::target_type derived(spec.root_id, derived_id);
            info.emplace(derived, manifest::target_info{key, key_path});
        }
    }

    return manifest(std::move(targets), std::move(info));
}

}
