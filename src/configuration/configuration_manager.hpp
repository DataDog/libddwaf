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

namespace ddwaf {

class configuration_manager {
public:
    configuration_manager() = default;
    ~configuration_manager() = default;
    configuration_manager(configuration_manager &&) = delete;
    configuration_manager(const configuration_manager &) = delete;
    configuration_manager &operator=(configuration_manager &&) = delete;
    configuration_manager &operator=(const configuration_manager &) = delete;

    bool add_or_update(const std::string &path, raw_configuration &root, base_ruleset_info &info);
    bool remove(const std::string &path);

    std::pair<const configuration_spec &, change_set> consolidate();

protected:
    void remove_config(const configuration_change_spec &cfg);

    void load(
        raw_configuration::map &root, configuration_collector &collector, base_ruleset_info &info);

    std::unordered_map<std::string, configuration_change_spec> configs_;
    configuration_spec global_config_;
    change_set changes_{change_set::none};
    object_limits limits_;
};

} // namespace ddwaf
