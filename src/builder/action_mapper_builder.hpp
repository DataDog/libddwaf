// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <boost/unordered/unordered_flat_map.hpp>
#include <map>
#include <memory>
#include <string>
#include <string_view>

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

    void set_action(const std::string &id, std::string type,
        boost::unordered_flat_map<std::string, std::string> parameters);

    [[nodiscard]] static const action_parameters &get_default_action(std::string_view id);

    std::shared_ptr<const action_mapper> build_shared();

    // Used for testing
    action_mapper build();

protected:
    std::map<std::string, action_parameters, std::less<>> action_by_id_;
    static const std::map<std::string, action_parameters, std::less<>> default_actions_;
};

} // namespace ddwaf
