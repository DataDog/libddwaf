// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>

#include "configuration/common/configuration.hpp"
#include "parameter.hpp"
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

    bool add(const std::string &path, parameter::map &root, base_ruleset_info &info);
    bool update(const std::string &path, parameter::map &root, base_ruleset_info &info);
    bool remove(const std::string &path);

    merged_configuration_spec consolidate() const;

protected:
    void remove_config_ids(
        const std::unordered_map<std::string, configuration_spec>::const_iterator &it);

    configuration_spec load(parameter::map &root, base_ruleset_info &info);

    spec_id_tracker ids_;
    std::unordered_map<std::string, configuration_spec> configs_;
    object_limits limits_;
};

} // namespace ddwaf
