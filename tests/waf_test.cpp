// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestWaf, RootAddresses)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::null_ruleset_info info;
    ddwaf::waf instance{
        rule, info, ddwaf::object_limits(), ddwaf_object_free, std::make_shared<obfuscator>()};
    ddwaf_object_free(&rule);

    std::set<std::string_view> available_addresses{"value1", "value2"};
    for (const auto *address : instance.get_root_addresses()) {
        EXPECT_NE(available_addresses.find(address), available_addresses.end());
    }
}

TEST(TestWaf, BasicContextRun)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::null_ruleset_info info;
    ddwaf::waf instance{
        rule, info, ddwaf::object_limits(), ddwaf_object_free, std::make_shared<obfuscator>()};
    ddwaf_object_free(&rule);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

    auto *ctx = instance.create_context();
    EXPECT_EQ(ctx->run(root, std::nullopt, LONG_TIME), DDWAF_MATCH);
    delete ctx;
}

TEST(TestWaf, RuleDisabledInRuleset)
{
    auto rule = readFile("rule_disabled.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::null_ruleset_info info;
    ddwaf::waf instance{
        rule, info, ddwaf::object_limits(), ddwaf_object_free, std::make_shared<obfuscator>()};
    ddwaf_object_free(&rule);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

        auto *ctx = instance.create_context();
        EXPECT_EQ(ctx->run(root, std::nullopt, LONG_TIME), DDWAF_OK);
        delete ctx;
    }
}

TEST(TestWaf, AddressUniqueness)
{
    absl::flat_hash_set<std::size_t> indices;

    {
        std::size_t hash = std::hash<std::string>()("grpc.server.request.message");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("grpc.server.request.metadata");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("http.client_ip");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("server.request.body");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("server.request.headers.no_cookies");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("server.request.path_params");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("server.request.query");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("server.request.uri.raw");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("server.response.status");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
    {
        std::size_t hash = std::hash<std::string>()("usr.id");
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
}
