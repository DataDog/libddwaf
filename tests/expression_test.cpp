// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "expression.hpp"
#include "matcher/regex_match.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

TEST(TestExpression, SimpleMatch)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>(".*", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);

    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .address = "server.request.query",
                                .path = {},
                                .value = "value",
                                .highlight = "value"});
}

TEST(TestExpression, MultiInputMatchOnSecond)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");
    builder.add_target("server.request.body");

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);

        auto matches = expr->get_matches(cache);
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .address = "server.request.body",
                                    .path = {},
                                    .value = "value",
                                    .highlight = "value"});
    }
}

TEST(TestExpression, DuplicateInput)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    expression::cache_type cache;
    ddwaf::object_store store;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }
}

TEST(TestExpression, MatchDuplicateInputNoCache)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);

        auto matches = expr->get_matches(cache);
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .address = "server.request.query",
                                    .path = {},
                                    .value = "value",
                                    .highlight = "value"});
    }
}

TEST(TestExpression, TwoConditionsSingleInputNoMatch)
{
    expression_builder builder(2);

    builder.start_condition<matcher::regex_match>("value", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<matcher::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    expression::cache_type cache;
    ddwaf::object_store store;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad_value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }
}

TEST(TestExpression, TwoConditionsSingleInputMatch)
{
    expression_builder builder(2);

    builder.start_condition<matcher::regex_match>("value", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<matcher::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
}

TEST(TestExpression, TwoConditionsMultiInputSingleEvalMatch)
{
    expression_builder builder(2);

    builder.start_condition<matcher::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<matcher::regex_match>("body", 0, true);
    builder.add_target("server.request.body");

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "query"));
    ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "body"));

    store.insert(root);

    ddwaf::timer deadline{2s};

    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
}

TEST(TestExpression, TwoConditionsMultiInputMultiEvalMatch)
{
    expression_builder builder(2);

    builder.start_condition<matcher::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<matcher::regex_match>("body", 0, true);
    builder.add_target("server.request.body");

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "query"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "body"));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, "red-herring"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }
}

TEST(TestExpression, MatchWithKeyPath)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>(".*", 0, true);
    builder.add_target("server.request.query", {"key"});
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object submap;
    ddwaf_object tmp;
    ddwaf_object_map(&submap);
    ddwaf_object_map_add(&submap, "key", ddwaf_object_string(&tmp, "value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &submap);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .address = "server.request.query",
                                .path = {"key"},
                                .value = "value",
                                .highlight = "value"});
}

TEST(TestExpression, MatchWithTransformer)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("value", 0, true);
    builder.add_target("server.request.query", {}, {transformer_id::lowercase});
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "VALUE"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .address = "server.request.query",
                                .path = {},
                                .value = "value",
                                .highlight = "value"});
}

TEST(TestExpression, MatchWithMultipleTransformers)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("^ value $", 0, true);
    builder.add_target("server.request.query", {},
        {transformer_id::compress_whitespace, transformer_id::lowercase});
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "    VALUE    "));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "^ value $",
                                .address = "server.request.query",
                                .path = {},
                                .value = " value ",
                                .highlight = " value "});
}

TEST(TestExpression, MatchOnKeys)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("value", 0, true);
    builder.add_target("server.request.query", {}, {}, expression::data_source::keys);
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "value", ddwaf_object_string(&tmp, "1729"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &value);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .address = "server.request.query",
                                .path = {"value"},
                                .value = "value",
                                .highlight = "value"});
}

TEST(TestExpression, MatchOnKeysWithTransformer)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>("value", 0, true);
    builder.add_target(
        "server.request.query", {}, {transformer_id::lowercase}, expression::data_source::keys);
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "VALUE", ddwaf_object_string(&tmp, "1729"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &value);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .address = "server.request.query",
                                .path = {"VALUE"},
                                .value = "value",
                                .highlight = "value"});
}

TEST(TestExpression, ExcludeInput)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>(".*", 0, true);
    builder.add_target("server.request.query");
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_FALSE(expr->eval(cache, store, {&root.array[0]}, {}, deadline).outcome);
}

TEST(TestExpression, ExcludeKeyPath)
{
    expression_builder builder(1);
    builder.start_condition<matcher::regex_match>(".*", 0, true);
    builder.add_target("server.request.query");
    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object map;
    ddwaf_object tmp;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &map);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_FALSE(expr->eval(cache, store, {&map.array[0]}, {}, deadline).outcome);
}
