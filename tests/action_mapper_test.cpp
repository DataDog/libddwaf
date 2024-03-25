// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <unordered_map>

#include "action_mapper.hpp"
#include "test.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestActionMapper, TypeToString)
{
    EXPECT_EQ(action_type_from_string("block_request"), action_type::block_request);
    EXPECT_EQ(action_type_from_string("redirect_request"), action_type::redirect_request);
    EXPECT_EQ(action_type_from_string("generate_stack"), action_type::generate_stack);
    EXPECT_EQ(action_type_from_string("generate_schema"), action_type::generate_schema);
    EXPECT_EQ(action_type_from_string("monitor"), action_type::monitor);
}

TEST(TestActionMapper, DefaultActions)
{
    action_mapper actions;

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    {
        const auto &action = actions.get_action("block");
        EXPECT_EQ(action->get().type, action_type::block_request);
        EXPECT_STR(action->get().type_str, "block_request");

        EXPECT_EQ(action->get().parameters.size(), 3);
        EXPECT_STRV(action->get().parameters.at("status_code"), "403");
        EXPECT_STRV(action->get().parameters.at("type"), "auto");
        EXPECT_STRV(action->get().parameters.at("grpc_status_code"), "10");
    }

    {
        const auto &action = actions.get_action("stack_trace");
        EXPECT_EQ(action->get().type, action_type::generate_stack);
        EXPECT_STR(action->get().type_str, "generate_stack");
        EXPECT_EQ(action->get().parameters.size(), 0);
    }

    {
        const auto &action = actions.get_action("extract_schema");
        EXPECT_EQ(action->get().type, action_type::generate_schema);
        EXPECT_STR(action->get().type_str, "generate_schema");
        EXPECT_EQ(action->get().parameters.size(), 0);
    }

    {
        const auto &action = actions.get_action("monitor");
        EXPECT_EQ(action->get().type, action_type::monitor);
        EXPECT_STR(action->get().type_str, "monitor");
        EXPECT_EQ(action->get().parameters.size(), 0);
    }
}

TEST(TestActionMapper, UnknownAction)
{
    action_mapper actions;

    EXPECT_FALSE(actions.contains("blorck"));
    EXPECT_FALSE(actions.contains("stack_traces"));
    EXPECT_FALSE(actions.contains("extract_scherma"));
    EXPECT_FALSE(actions.contains("mornitor"));

    EXPECT_FALSE(actions.get_action("blorck"));
    EXPECT_FALSE(actions.get_action("stack_traces"));
    EXPECT_FALSE(actions.get_action("extract_scherma"));
    EXPECT_FALSE(actions.get_action("mornitor"));

    EXPECT_THROW(auto _ = actions.get_action_ref("blorck"), std::out_of_range);
    EXPECT_THROW(auto _ = actions.get_action_ref("stack_traces"), std::out_of_range);
    EXPECT_THROW(auto _ = actions.get_action_ref("extract_scherma"), std::out_of_range);
    EXPECT_THROW(auto _ = actions.get_action_ref("mornitor"), std::out_of_range);
}

TEST(TestActionMapper, SetAction)
{
    action_mapper actions;

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    actions.set_action(
        "redirect", "redirect_request", {{"status_code", "33"}, {"location", "datadoghq"}});

    EXPECT_TRUE(actions.contains("redirect"));

    {
        const auto &action = actions.get_action("redirect");
        EXPECT_EQ(action->get().type, action_type::redirect_request);
        EXPECT_STR(action->get().type_str, "redirect_request");

        EXPECT_EQ(action->get().parameters.size(), 2);
        EXPECT_STRV(action->get().parameters.at("status_code"), "33");
        EXPECT_STRV(action->get().parameters.at("location"), "datadoghq");
    }
}

TEST(TestActionMapper, SetActionAlias)
{
    action_mapper actions;

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    actions.set_action_alias("block", "redirect");

    EXPECT_TRUE(actions.contains("redirect"));

    {
        const auto &action = actions.get_action("redirect");
        EXPECT_EQ(action->get().type, action_type::block_request);
        EXPECT_STR(action->get().type_str, "block_request");

        EXPECT_EQ(action->get().parameters.size(), 3);
        EXPECT_STRV(action->get().parameters.at("status_code"), "403");
        EXPECT_STRV(action->get().parameters.at("type"), "auto");
        EXPECT_STRV(action->get().parameters.at("grpc_status_code"), "10");
    }
}

TEST(TestActionMapper, SetInvalidActionAlias)
{
    action_mapper actions;
    EXPECT_THROW(actions.set_action_alias("blorck", "redirect"), std::runtime_error);
}

TEST(TestActionMapper, OverrideDefaultAction)
{
    action_mapper actions;

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    actions.set_action(
        "block", "redirect_request", {{"status_code", "33"}, {"location", "datadoghq"}});
    EXPECT_TRUE(actions.contains("block"));

    {
        const auto &action = actions.get_action("block");
        EXPECT_EQ(action->get().type, action_type::redirect_request);
        EXPECT_STR(action->get().type_str, "redirect_request");

        EXPECT_EQ(action->get().parameters.size(), 2);
        EXPECT_STRV(action->get().parameters.at("status_code"), "33");
        EXPECT_STRV(action->get().parameters.at("location"), "datadoghq");
    }
}

TEST(TestActionMapper, DuplicateAction)
{
    action_mapper actions;

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    actions.set_action(
        "redirect", "redirect_request", {{"status_code", "33"}, {"location", "datadoghq"}});
    EXPECT_THROW(actions.set_action("redirect", "redirect_request", {}), std::runtime_error);
}

} // namespace
