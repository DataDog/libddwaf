// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include "utils.hpp"

namespace ddwaf {

enum class action_type { block_request, redirect_request, generate_stack, unknown };

struct action_spec {
    action_type type;
    std::unordered_map<std::string, std::string> parameters;
};

using action_spec_ref =
    std::variant<action_spec, std::reference_wrapper<const action_spec>, std::monostate>;

class action_mapper {
public:
    action_mapper();
    ~action_mapper() = default;
    action_mapper(const action_mapper &) = default;
    action_mapper(action_mapper &&) = default;
    action_mapper &operator=(const action_mapper &) = default;
    action_mapper &operator=(action_mapper &&) = default;

    void set_action(
        std::string id, action_type type, std::unordered_map<std::string, std::string> parameters);
    action_spec_ref get_action(const std::string &id) const;
    bool contains(const std::string &id) const { return action_by_id_.contains(id); }

protected:
    std::unordered_map<std::string, action_spec> action_by_id_;
};

} // namespace ddwaf
