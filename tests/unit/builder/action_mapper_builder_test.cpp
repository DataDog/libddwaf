// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <unordered_map>

#include "action_mapper.hpp"
#include "builder/action_mapper_builder.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestActionMapperBuilder, TypeToString)
{
    EXPECT_EQ(action_type_from_string("block_request"), action_type::block_request);
    EXPECT_EQ(action_type_from_string("redirect_request"), action_type::redirect_request);
    EXPECT_EQ(action_type_from_string("generate_stack"), action_type::generate_stack);
    EXPECT_EQ(action_type_from_string("generate_schema"), action_type::generate_schema);
    EXPECT_EQ(action_type_from_string("monitor"), action_type::monitor);
}

TEST(TestActionMapperBuilder, DefaultActions)
{
    action_mapper actions = action_mapper_builder().build();

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    {
        const auto &action = actions.at("block");
        EXPECT_EQ(action.type, action_type::block_request);
        EXPECT_STR(action.type_str, "block_request");

        EXPECT_EQ(action.parameters.size(), 3);
        EXPECT_EQ(std::get<uint64_t>(action.parameters.at("status_code")), 403);
        EXPECT_STRV(std::get<std::string>(action.parameters.at("type")), "auto");
        EXPECT_EQ(std::get<uint64_t>(action.parameters.at("grpc_status_code")), 10);
    }

    {
        const auto &action = actions.at("stack_trace");
        EXPECT_EQ(action.type, action_type::generate_stack);
        EXPECT_STR(action.type_str, "generate_stack");
        EXPECT_EQ(action.parameters.size(), 0);
    }

    {
        const auto &action = actions.at("extract_schema");
        EXPECT_EQ(action.type, action_type::generate_schema);
        EXPECT_STR(action.type_str, "generate_schema");
        EXPECT_EQ(action.parameters.size(), 0);
    }

    {
        const auto &action = actions.at("monitor");
        EXPECT_EQ(action.type, action_type::monitor);
        EXPECT_STR(action.type_str, "monitor");
        EXPECT_EQ(action.parameters.size(), 0);
    }
}

TEST(TestActionMapperBuilder, UnknownAction)
{
    action_mapper actions = action_mapper_builder().build();

    EXPECT_FALSE(actions.contains("blorck"));
    EXPECT_FALSE(actions.contains("stack_traces"));
    EXPECT_FALSE(actions.contains("extract_scherma"));
    EXPECT_FALSE(actions.contains("mornitor"));

    EXPECT_THROW(auto _ = actions.at("blorck"), std::out_of_range);
    EXPECT_THROW(auto _ = actions.at("stack_traces"), std::out_of_range);
    EXPECT_THROW(auto _ = actions.at("extract_scherma"), std::out_of_range);
    EXPECT_THROW(auto _ = actions.at("mornitor"), std::out_of_range);
}

TEST(TestActionMapperBuilder, SetAction)
{
    action_mapper_builder builder;
    builder.set_action(
        "redirect", "redirect_request", {{"status_code", 33ULL}, {"location", "datadoghq"}});

    auto actions = builder.build();

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    EXPECT_TRUE(actions.contains("redirect"));

    {
        const auto &action = actions.at("redirect");
        EXPECT_EQ(action.type, action_type::redirect_request);
        EXPECT_STR(action.type_str, "redirect_request");

        EXPECT_EQ(action.parameters.size(), 2);
        EXPECT_EQ(std::get<uint64_t>(action.parameters.at("status_code")), 33);
        EXPECT_STRV(std::get<std::string>(action.parameters.at("location")), "datadoghq");
    }
}

TEST(TestActionMapperBuilder, OverrideDefaultAction)
{
    action_mapper_builder builder;
    builder.set_action(
        "block", "redirect_request", {{"status_code", 33ULL}, {"location", "datadoghq"}});

    auto actions = builder.build();

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    {
        const auto &action = actions.at("block");
        EXPECT_EQ(action.type, action_type::redirect_request);
        EXPECT_STR(action.type_str, "redirect_request");

        EXPECT_EQ(action.parameters.size(), 2);
        EXPECT_EQ(std::get<uint64_t>(action.parameters.at("status_code")), 33);
        EXPECT_STRV(std::get<std::string>(action.parameters.at("location")), "datadoghq");
    }
}

TEST(TestActionMapperBuilder, DuplicateAction)
{
    action_mapper_builder builder;
    builder.set_action(
        "redirect", "redirect_request", {{"status_code", "33"}, {"location", "datadoghq"}});
    EXPECT_THROW(builder.set_action("redirect", "redirect_request", {}), std::runtime_error);
}

TEST(TestActionMapperBuilder, DuplicateDefaultAction)
{
    action_mapper_builder builder;
    builder.set_action(
        "block", "redirect_request", {{"status_code", 33ULL}, {"location", "datadoghq"}});
    EXPECT_THROW(builder.set_action("block", "redirect_request", {}), std::runtime_error);
    auto actions = builder.build();

    EXPECT_TRUE(actions.contains("block"));
    EXPECT_TRUE(actions.contains("stack_trace"));
    EXPECT_TRUE(actions.contains("extract_schema"));
    EXPECT_TRUE(actions.contains("monitor"));

    {
        const auto &action = actions.at("block");
        EXPECT_EQ(action.type, action_type::redirect_request);
        EXPECT_STR(action.type_str, "redirect_request");

        EXPECT_EQ(action.parameters.size(), 2);
        EXPECT_EQ(std::get<uint64_t>(action.parameters.at("status_code")), 33);
        EXPECT_STRV(std::get<std::string>(action.parameters.at("location")), "datadoghq");
    }
}

} // namespace
