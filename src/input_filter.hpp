// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <stack>
#include <vector>

#include <clock.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <object_filter.hpp>

namespace ddwaf {

class input_filter {
public:
    struct filter_result {
        bool skip{false};
        //object_filter ofilter;
    };

    struct input_set {
        void insert(manifest::target_type target) { targets_[target] = {}; }

        void insert(manifest::target_type target,
          std::vector<std::string> &&key_path) {
            auto it = targets_.find(target);
            if (it != targets_.end()) {
                if (it->second.empty()) {
                    return;
                }
                it->second.emplace(std::move(key_path));
            } else {
                targets_[target].emplace(std::move(key_path));
            }
        }

        [[nodiscard]] bool empty() const { return targets_.empty(); }

        std::unordered_map<manifest::target_type,
            std::unordered_set<std::vector<std::string>>> targets_;
    };

    input_filter() = default;

    void insert(const input_filter::input_set &filter_targets) {
        for (const auto &[target, key_paths] : filter_targets.targets_) {
            targets_[target].skip = true;
        }
    }

    std::optional<filter_result> find(manifest::target_type target) const {
        if (auto it = targets_.find(target); it != targets_.end()) {
            return {it->second};
        }
        return std::nullopt;
    }

    bool valid() const { return !targets_.empty(); }
protected:
    std::unordered_map<manifest::target_type, filter_result> targets_;
};

} // namespace ddwaf
