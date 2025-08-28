// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string_view>

#include "action_mapper.hpp"

namespace ddwaf {
action_type action_type_from_string(std::string_view type)
{
    if (type == "block_request") {
        return action_type::block_request;
    }
    if (type == "redirect_request") {
        return action_type::redirect_request;
    }
    if (type == "generate_stack") {
        return action_type::generate_stack;
    }
    if (type == "generate_schema") {
        return action_type::generate_schema;
    }
    if (type == "monitor") {
        return action_type::monitor;
    }
    // Unknown actions are valid, but provide no semantic value
    return action_type::unknown;
}

} // namespace ddwaf
