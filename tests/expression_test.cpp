// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "PWTransformer.h"
#include "expression.hpp"
#include "test.h"

using namespace ddwaf;

TEST(TestExpression, SimpleMatch)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::regex_match>(".*", 0, true);
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
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));

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
    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
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

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));

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
    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestExpression, MatchDuplicateInputNoCache)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
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
        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
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
        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));

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

    builder.start_condition<rule_processor::regex_match>("value", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_target("server.request.query");

    auto expr = builder.build();

    expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad_value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestExpression, TwoConditionsSingleInputMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("value", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
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
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));
}

TEST(TestExpression, TwoConditionsMultiInputSingleEvalMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("body", 0, true);
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

    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));
}

TEST(TestExpression, TwoConditionsMultiInputMultiEvalMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("body", 0, true);
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

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
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

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestExpression, SingleObjectChain)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^thermometer$", 0, true);
    builder.add_target("match.0.object");

    auto expr = builder.build();

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, "some query"));
        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object query;
        ddwaf_object_map(&query);
        ddwaf_object_map_add(&query, "value1", ddwaf_object_string(&tmp, "some query"));
        ddwaf_object_map_add(&query, "value2", ddwaf_object_string(&tmp, "thermometer"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", &query);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestExpression, SingleScalarChain)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^query$", 0, true);
    builder.add_target("match.0.scalar");

    auto expr = builder.build();

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object query;

        ddwaf_object_map(&query);
        ddwaf_object_map_add(&query, "value1", ddwaf_object_string(&tmp, "some query"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", &query);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object query;

        ddwaf_object_map(&query);
        ddwaf_object_map_add(&query, "value2", ddwaf_object_string(&tmp, "some query"));
        ddwaf_object_map_add(&query, "value1", ddwaf_object_string(&tmp, "query"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", &query);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));

        auto matches = expr->get_matches(cache);
        EXPECT_MATCHES(matches,
            {.op = "match_regex",
                .op_value = "query",
                .address = "server.request.query",
                .path = {"value1"},
                .value = "query",
                .highlight = "query"},
            {.op = "match_regex",
                .op_value = "^query$",
                .address = "match.0.scalar",
                .path = {},
                .value = "query",
                .highlight = "query"});
    }
}

TEST(TestExpression, SingleHighlightChain)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^query$", 0, true);
    builder.add_target("match.0.highlight");

    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "some query"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline));

    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches,
        {.op = "match_regex",
            .op_value = "query",
            .address = "server.request.query",
            .path = {},
            .value = "some query",
            .highlight = "query"},
        {.op = "match_regex",
            .op_value = "^query$",
            .address = "match.0.highlight",
            .path = {},
            .value = "query",
            .highlight = "query"});
}
