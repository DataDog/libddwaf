// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "PWTransformer.h"
#include "expression.hpp"
#include "test.h"

using namespace ddwaf;

using expression = experimental::expression;
using expression_builder = experimental::expression_builder;

TEST(TestExpressionBuilder, SimpleMatch)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::regex_match>(".*", 0, true);
    builder.add_global_target("server.request.query");

    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
}

TEST(TestExpressionBuilder, MultiInputMatchOnSecond)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_global_target("server.request.query");
    builder.add_global_target("server.request.body");

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

        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, DuplicateInput)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_global_target("server.request.query");

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

        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, MatchDuplicateInputNoCache)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_global_target("server.request.query");

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
        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
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
        EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, TwoConditionsSingleInputNoMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("value", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_global_target("server.request.query");

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

        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, TwoConditionsSingleInputMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("value", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^value$", 0, true);
    builder.add_global_target("server.request.query");

    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
}

TEST(TestExpressionBuilder, TwoConditionsMultiInputSingleEvalMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("body", 0, true);
    builder.add_global_target("server.request.body");

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

    EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
}

TEST(TestExpressionBuilder, TwoConditionsMultiInputMultiEvalMatch)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("body", 0, true);
    builder.add_global_target("server.request.body");

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

        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
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

        EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, SingleObjectChain)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^thermometer$", 0, true);
    builder.add_local_target("match.0.object", 0, expression::eval_entity::object);

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
        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
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
        EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, SingleScalarChain)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^query$", 0, true);
    builder.add_local_target("match.0.scalar", 0, expression::eval_entity::scalar);

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
        EXPECT_FALSE(expr->eval(cache, store, {}, deadline));
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
        EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
    }
}

TEST(TestExpressionBuilder, SingleHighlightChain)
{
    expression_builder builder(2);

    builder.start_condition<rule_processor::regex_match>("query", 0, true);
    builder.add_global_target("server.request.query");

    builder.start_condition<rule_processor::regex_match>("^query$", 0, true);
    builder.add_local_target("match.0.highlight", 0, expression::eval_entity::highlight);

    auto expr = builder.build();

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "some query"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, deadline));
}
