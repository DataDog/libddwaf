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

namespace std {
template <>
struct hash<std::vector<std::string>>
{
    std::size_t operator()(const std::vector<std::string>& k) const {
        std::size_t hash = 0;
        for (const auto &str : k) {
            hash ^= std::hash<std::string>{}(str);
        }
        return hash;
    }
};
}

namespace ddwaf
{
class manifest {
public:
    using target_type = uint32_t;
    struct target_info {
        std::string name;
        std::vector<std::string> key_path;
    };

    manifest() = default;
    manifest(std::unordered_map<std::string, target_type> &&targets,
        std::unordered_map<target_type, target_info> &&info):
        targets_(std::move(targets)), info_(std::move(info))
    {
        root_addresses_.reserve(targets_.size());
        for (auto &[k, v] : targets_) {
            root_addresses_.push_back(k.c_str());
        }
    }

    manifest(manifest&&)      = default;
    manifest(const manifest&) = delete;
    manifest& operator=(manifest&&) = default;
    manifest& operator=(const manifest&) = delete;

    bool empty() { return targets_.empty(); }
    bool contains(const std::string& name) {
        return targets_.find(name) != targets_.end();
    }

    std::pair<bool, target_type> get_target(const std::string& name) const {
        auto it = targets_.find(name);
        if (it == targets_.end()) {
            return {false, 0};
        }
        return {true, it->second};
    }

    const target_info& get_target_info(target_type target) const {
        static target_info empty_info = {};
        auto it = info_.find(target);
        if (it == info_.end()) {
            return empty_info;
        }
        return it->second;
    }

    const std::vector<const char*>& get_root_addresses() const {
        return root_addresses_;
    }

    static target_type get_root(target_type target) {
        return target & 0xFFFF0000;
    }

protected:
    std::unordered_map<std::string, target_type> targets_{};
    std::unordered_map<target_type, target_info> info_{};

    // Root address memory to be returned to the API caller
    std::vector<const char*> root_addresses_;
};

class manifest_builder {
public:
    manifest::target_type insert(const std::string& root,
        const std::vector<std::string>& key_path);

    manifest build_manifest();

protected:
    // The spec allows keeping track of targets which share the same root
    // address, but a different key_path. The root target ID is always
    // the same for all of them, but the derived ID is specific to
    // each key_path.
    struct target_spec {
        uint16_t root_id;
        uint16_t derived_id{0};
        std::unordered_map<std::vector<std::string>, uint16_t> derived;
    };

    static constexpr manifest::target_type generate_target(
        uint16_t root, uint16_t id) {
        return static_cast<uint32_t>(root) << 16 | id;
    }

    std::unordered_map<std::string, target_spec> targets_;
    uint16_t index_{0};
};

}

