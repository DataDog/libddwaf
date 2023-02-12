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

void manifest::update_targets(const std::unordered_set<target_type> &valid_targets)
{
    for (auto it = targets_.begin(); it != targets_.end();) {
        if (valid_targets.find(it->second) == valid_targets.end()) {
            it = targets_.erase(it);
        } else {
            ++it;
        }
    }
}
/*manifest::target_type manifest_builder::insert(*/
// const std::string &root, const std::vector<std::string> &key_path)
//{
// auto it = targets_.find(root);
// if (it == targets_.end()) {
// auto [new_it, res] = targets_.emplace(root, target_spec{++index_, 0, {}});
//// assume res = true
// it = new_it;
//}

// auto &[root_id, derived_id, derived_map] = it->second;

// if (key_path.empty()) {
// return generate_target(root_id, 0);
//}

// auto derived_it = derived_map.find(key_path);
// if (derived_it == derived_map.end()) {
// auto [new_it, res] = derived_map.emplace(key_path, ++derived_id);
// derived_it = new_it;
//}

// return generate_target(root_id, derived_it->second);
//}

// manifest manifest_builder::build_manifest()
//{
// std::unordered_map<std::string, manifest::target_type> targets;
// std::unordered_map<manifest::target_type, manifest::target_info> info;

// for (auto &[key, spec] : targets_) {
// auto root = generate_target(spec.root_id, 0);

// targets.emplace(key, root);
// info.emplace(root, manifest::target_info{key, {}});

// for (auto &[key_path, derived_id] : spec.derived) {
// auto derived = generate_target(spec.root_id, derived_id);
// info.emplace(derived, manifest::target_info{key, key_path});
//}
//}

// return {std::move(targets), std::move(info)};
//}

} // namespace ddwaf
