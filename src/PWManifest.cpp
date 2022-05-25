// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWManifest.h>
#include <utils.h>

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
    } else {
        root_target = root_it->second;
    }

    // Targets with key path should have a different name than the root
    if (name == root) { return root_target; }

    // The target already exists, return that target
    auto current_it = targets_.find(name);
    if (current_it != targets_.end()) { return current_it->second; }

    // Not already in the manifest
    target_type current_target = target_counter_++;
    targets_.emplace(name, current_target);
    info_.emplace(current_target, target_info{root_target, key_path});
    derived_[root_target].emplace(current_target);

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

}

PWManifest::ARG_ID PWManifest::insert(std::string_view name, PWManifest::ArgDetails&& arg)
{
    auto [it, result] = argManifest.emplace(counter, std::move(arg));
    (void) result; // unused
    argIDTable.emplace(name, counter);

    if (root_address_set.find(it->second.inheritFrom) == root_address_set.end())
    {
        root_address_set.emplace(it->second.inheritFrom);
        root_addresses.push_back(it->second.inheritFrom.c_str());
    }

    return counter++;
}

bool PWManifest::hasTarget(const std::string& string) const
{
    return argIDTable.find(string) != argIDTable.cend();
}

PWManifest::ARG_ID PWManifest::getTargetArgID(const std::string& target) const
{
    return argIDTable.find(target)->second;
}

const PWManifest::ArgDetails& PWManifest::getDetailsForTarget(const PWManifest::ARG_ID& argID) const
{
    // We can't really return a dummy object when the key doesn't exist so the caller need to call `hasTarget` first.
    return argManifest.find(argID)->second;
}

const std::string& PWManifest::getTargetName(const PWManifest::ARG_ID& target) const
{
    static const std::string& dummyTargetName("<invalid>");

    for (const auto& argIDDefinition : argIDTable)
    {
        if (argIDDefinition.second == target)
        {
            return argIDDefinition.first;
        }
    }

    return dummyTargetName;
}

void PWManifest::findImpactedArgs(const std::unordered_set<std::string>& newFields, std::unordered_set<PWManifest::ARG_ID>& argsImpacted) const
{
    argsImpacted.reserve(argManifest.size());

    for (const auto& param : argManifest)
    {
        if (newFields.find(param.second.inheritFrom) != newFields.cend())
        {
            argsImpacted.insert(param.first);
        }
    }
}
