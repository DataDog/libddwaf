// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>

#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ruleset_info.hpp"

#include "re2.h"

namespace ddwaf {

class configuration_manager {
public:
    configuration_manager() = default;
    ~configuration_manager() = default;
    configuration_manager(configuration_manager &&) = delete;
    configuration_manager(const configuration_manager &) = delete;
    configuration_manager &operator=(configuration_manager &&) = delete;
    configuration_manager &operator=(const configuration_manager &) = delete;

    bool add_or_update(const std::string &path, raw_configuration &root, ruleset_info &info);
    bool remove(const std::string &path);

    std::pair<const configuration_spec &, change_set> consolidate();

    std::vector<std::string_view> get_config_paths() const
    {
        std::vector<std::string_view> paths;
        paths.reserve(configs_.size());
        for (const auto &[path, _] : configs_) { paths.emplace_back(path); }
        return paths;
    }

    std::vector<std::string_view> get_filtered_config_paths(re2::RE2 &filter) const
    {
        std::vector<std::string_view> paths;
        paths.reserve(configs_.size());
        for (const auto &[path, _] : configs_) {
            const std::string_view ref(path.data(), path.size());
            if (!filter.Match(ref, 0, path.size(), re2::RE2::UNANCHORED, nullptr, 0)) {
                continue;
            }
            paths.emplace_back(path);
        }
        return paths;
    }

protected:
    void remove_config(const configuration_change_spec &cfg);

    static bool load(
        raw_configuration::map &root, configuration_collector &collector, ruleset_info &info);

    std::unordered_map<std::string, configuration_change_spec> configs_;
    configuration_spec global_config_;
    change_set changes_{change_set::none};
};

} // namespace ddwaf
