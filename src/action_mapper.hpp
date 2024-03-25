// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <map>
#include <string>
#include <string_view>
#include <unordered_map>

#include "utils.hpp"

namespace ddwaf {

enum class action_type : uint8_t {
    none = 0,
    unknown = 1,
    generate_stack = 2,
    generate_schema = 3,
    monitor = 4,
    block_request = 5,
    redirect_request = 6, // Redirect must always be the last action
                          // as the value is used to serve as precedence
};

inline bool is_blocking_action(action_type type)
{
    return type == action_type::block_request || type == action_type::redirect_request;
}

struct action_spec {
    action_type type;
    std::string type_str;
    std::unordered_map<std::string, std::string> parameters;
};

class action_mapper {
public:
    action_mapper();
    ~action_mapper() = default;
    action_mapper(const action_mapper &) = default;
    action_mapper(action_mapper &&) = default;
    action_mapper &operator=(const action_mapper &) = default;
    action_mapper &operator=(action_mapper &&) = default;

    void set_action_alias(std::string_view id, std::string alias);

    void set_action(
        std::string id, std::string type, std::unordered_map<std::string, std::string> parameters);
    [[nodiscard]] optional_ref<const action_spec> get_action(std::string_view id) const;
    [[nodiscard]] bool contains(std::string_view id) const
    {
        return action_by_id_.find(id) != action_by_id_.end();
    }
    [[nodiscard]] std::size_t size() const { return action_by_id_.size(); }

protected:
    std::map<std::string, action_spec, std::less<>> action_by_id_;
    static const std::map<std::string, action_spec, std::less<>> default_actions_;
};

} // namespace ddwaf
