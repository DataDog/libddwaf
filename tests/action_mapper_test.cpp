// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "action_mapper.hpp"
#include "test.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestActionMapper, DefaultActions)
{
    action_mapper actions;

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));

    {
        const auto &action = actions.get_action("block");
        EXPECT_EQ(action->get().type, action_type::block_request);
        EXPECT_STR(action->get().type_str, "block_request");

        std::unordered_map<std::string_view, std::string_view> parameters{
            action->get().parameters.begin(), action->get().parameters.end()};
        EXPECT_STRV(parameters["status_code"], "403");
        EXPECT_STRV(parameters["type"], "auto");
        EXPECT_STRV(parameters["grpc_status_code"], "10");
    }

    {
        const auto &action = actions.get_action("stack_trace");
        EXPECT_EQ(action->get().type, action_type::generate_stack);
        EXPECT_STR(action->get().type_str, "generate_stack");
    }

    {
        const auto &action = actions.get_action("extract_schema");
        EXPECT_EQ(action->get().type, action_type::generate_schema);
        EXPECT_STR(action->get().type_str, "generate_schema");
    }
}

} // namespace
