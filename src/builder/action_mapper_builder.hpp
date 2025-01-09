// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "action_mapper.hpp"

namespace ddwaf {

class action_mapper_builder {
public:
    action_mapper_builder() = default;
    ~action_mapper_builder() = default;
    action_mapper_builder(const action_mapper_builder &) = delete;
    action_mapper_builder(action_mapper_builder &&) = delete;
    action_mapper_builder &operator=(const action_mapper_builder &) = delete;
    action_mapper_builder &operator=(action_mapper_builder &&) = delete;

    void alias_default_action_to(std::string_view default_id, std::string alias);

    void set_action(
        std::string id, std::string type, std::unordered_map<std::string, std::string> parameters);

    [[nodiscard]] static const action_parameters &get_default_action(std::string_view id);

    std::shared_ptr<action_mapper> build_shared();

    // Used for testing
    action_mapper build();

protected:
    std::map<std::string, action_parameters, std::less<>> action_by_id_;
    static const std::map<std::string, action_parameters, std::less<>> default_actions_;
};

} // namespace ddwaf
