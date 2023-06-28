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
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));
        cond.processor = std::make_unique<rule_processor::regex_match>(".*", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    experimental::expression::cache_type cache;
    EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
}

TEST(TestExpression, MultiInputMatchOnSecond)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition cond;

        {
            experimental::condition::target_type target;
            target.name = "server.request.query";
            target.root = get_target_index(target.name);
            cond.targets.emplace_back(std::move(target));
        }

        {
            experimental::condition::target_type target;
            target.name = "server.request.body";
            target.root = get_target_index(target.name);
            cond.targets.emplace_back(std::move(target));
        }

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("^value$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    ddwaf::object_store store;
    experimental::expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "value"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, DuplicateInput)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("^value$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    experimental::expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, MatchDuplicateInputNoCache)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("^value$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        experimental::expression::cache_type cache;
        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        experimental::expression::cache_type cache;
        EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, TwoConditionsSingleInputNoMatch)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("value", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("^value$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    experimental::expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "bad_value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, TwoConditionsSingleInputMatch)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("value", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("^value$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    experimental::expression::cache_type cache;
    EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
}

TEST(TestExpression, TwoConditionsMultiInputSingleEvalMatch)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("query", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.name = "server.request.body";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("body", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    ddwaf::object_store store;
    experimental::expression::cache_type cache;

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "query"));
    ddwaf_object_map_add(&root, "server.request.body", ddwaf_object_string(&tmp, "body"));

    store.insert(root);

    ddwaf::timer deadline{2s};

    EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
}

TEST(TestExpression, TwoConditionsMultiInputMultiEvalMatch)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("query", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.name = "server.request.body";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("body", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    ddwaf::object_store store;
    experimental::expression::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "query"));

        store.insert(root);

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
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

        EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, SingleObjectChain)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("query", 0, true);
        cond.dependents.object.emplace(1);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.scope = experimental::condition::eval_scope::local;
        target.condition_index = 0;
        target.entity = experimental::condition::eval_entity::object;
        target.name = "match.0.object";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("^thermometer$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, "some query"));
        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        experimental::expression::cache_type cache;
        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
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

        experimental::expression::cache_type cache;
        EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, SingleScalarChain)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("query", 0, true);
        cond.dependents.object.emplace(1);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.scope = experimental::condition::eval_scope::local;
        target.condition_index = 0;
        target.entity = experimental::condition::eval_entity::scalar;
        target.name = "match.0.scalar";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("^query$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object query;

        ddwaf_object_map(&query);
        ddwaf_object_map_add(&query, "value1", ddwaf_object_string(&tmp, "some query"));
        ddwaf_object_map_add(&query, "value2", ddwaf_object_string(&tmp, "query"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", &query);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        experimental::expression::cache_type cache;
        EXPECT_FALSE(expr.eval(cache, store, {}, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object query;

        ddwaf_object_map(&query);
        ddwaf_object_map_add(&query, "value1", ddwaf_object_string(&tmp, "query"));
        ddwaf_object_map_add(&query, "value2", ddwaf_object_string(&tmp, "some query"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.query", &query);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        experimental::expression::cache_type cache;
        EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
    }
}

TEST(TestExpression, SingleHighlightChain)
{
    std::vector<experimental::condition> conditions;

    {
        experimental::condition::target_type target;
        target.name = "server.request.query";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 0;
        cond.processor = std::make_unique<rule_processor::regex_match>("(query).*", 0, true);
        cond.dependents.object.emplace(1);
        conditions.emplace_back(std::move(cond));
    }

    {

        experimental::condition::target_type target;
        target.scope = experimental::condition::eval_scope::local;
        target.condition_index = 0;
        target.entity = experimental::condition::eval_entity::highlight;
        target.name = "match.0.highlight";
        target.root = get_target_index(target.name);

        experimental::condition cond;
        cond.targets.emplace_back(std::move(target));

        cond.index = 1;
        cond.processor = std::make_unique<rule_processor::regex_match>("^query$", 0, true);
        conditions.emplace_back(std::move(cond));
    }

    experimental::expression expr(std::move(conditions));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "some query"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    experimental::expression::cache_type cache;
    EXPECT_TRUE(expr.eval(cache, store, {}, deadline));
}
