// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "expression.hpp"
#include "matcher/regex_match.hpp"
#include "object_store.hpp"

using namespace ddwaf;
using namespace std::literals;

TEST(TestExpression, SimpleMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>(".*", 0, true);

    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "value"}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    auto res = expr->eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_FALSE(res.ephemeral);

    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_EQ(matches.size(), 1);
    EXPECT_FALSE(matches[0].ephemeral);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .highlight = "value",
                                .args = {{
                                    .value = "value",
                                    .address = "server.request.query",
                                }}});
}

TEST(TestExpression, SimpleNegatedMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match, false>(".*", 5, true);

    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "val"}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    auto res = expr->eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_FALSE(res.ephemeral);

    auto matches = expr->get_matches(cache);
    EXPECT_EQ(matches.size(), 1);
    EXPECT_FALSE(matches[0].ephemeral);
    EXPECT_MATCHES(matches, {.op = "!match_regex",
                                .op_value = ".*",
                                .highlight = "",
                                .args = {{
                                    .value = "val",
                                    .address = "server.request.query",
                                }}});
}

TEST(TestExpression, EphemeralMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>(".*", 0, true);

    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "value"}});

    ddwaf::object_store store;
    store.insert(std::move(root), object_store::attribute::ephemeral);

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    auto res = expr->eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.ephemeral);

    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_EQ(matches.size(), 1);
    EXPECT_TRUE(matches[0].ephemeral);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .highlight = "value",
                                .args = {{
                                    .value = "value",
                                    .address = "server.request.query",
                                }}});
}

TEST(TestExpression, MultiInputMatchOnSecondEval)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "bad"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.body", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_FALSE(res.ephemeral);

        auto matches = ddwaf::expression::get_matches(cache);
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .highlight = "value",
                                    .args = {{
                                        .value = "value",
                                        .address = "server.request.body",
                                    }}});
    }
}

TEST(TestExpression, EphemeralMatchOnSecondEval)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.body", "bad"}});

        store.insert(std::move(root), object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.body", "value"}});

        store.insert(std::move(root), object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.ephemeral);

        auto matches = ddwaf::expression::get_matches(cache);
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .highlight = "value",
                                    .args = {{
                                        .value = "value",
                                        .address = "server.request.body",
                                    }}});
    }
}

TEST(TestExpression, EphemeralMatchTwoConditions)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        auto root = owned_object::make_map({{"server.request.query", "value"}});
        store.insert(std::move(root), object_store::attribute::ephemeral);
    }

    {
        auto root = owned_object::make_map({{"server.request.body", "value"}});
        store.insert(std::move(root));
    }

    ddwaf::timer deadline{2s};

    auto res = expr->eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.ephemeral);

    auto matches = expr->get_matches(cache);
    EXPECT_MATCHES(matches,
        {.op = "match_regex",
            .op_value = "^value$",
            .highlight = "value",
            .args = {{
                .value = "value",
                .address = "server.request.query",
            }}},
        {.op = "match_regex",
            .op_value = "^value$",
            .highlight = "value",
            .args = {{
                .value = "value",
                .address = "server.request.body",
            }}});
}

TEST(TestExpression, EphemeralMatchOnFirstConditionFirstEval)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root), object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.body", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }
}

TEST(TestExpression, EphemeralMatchOnFirstConditionSecondEval)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.body", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root), object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.ephemeral);
    }
}

TEST(TestExpression, DuplicateInput)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    expression::cache_type cache;
    ddwaf::object_store store;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "bad"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_FALSE(res.ephemeral);
    }
}

TEST(TestExpression, DuplicateEphemeralInput)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    expression::cache_type cache;
    ddwaf::object_store store;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root), object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root), object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.ephemeral);
    }
}

TEST(TestExpression, MatchDuplicateInputNoCache)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "bad"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);

        auto matches = expr->get_matches(cache);
        EXPECT_EQ(matches.size(), 1);
        EXPECT_FALSE(matches[0].ephemeral);
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .highlight = "value",
                                    .args = {{
                                        .value = "value",
                                        .address = "server.request.query",
                                    }}});
    }
}

TEST(TestExpression, TwoConditionsSingleInputNoMatch)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("value", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    expression::cache_type cache;
    ddwaf::object_store store;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "bad_value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }
}

TEST(TestExpression, TwoConditionsSingleInputMatch)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("value", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "value"}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
}

TEST(TestExpression, TwoConditionsMultiInputSingleEvalMatch)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("query", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("body", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    auto root = owned_object::make_map(
        {{"server.request.query", "query"}, {"server.request.body", "body"}});

    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
}

TEST(TestExpression, TwoConditionsMultiInputMultiEvalMatch)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("query", 0, true);

    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("body", 0, true);

    auto expr = builder.build();

    ddwaf::object_store store;
    expression::cache_type cache;

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map({{"server.request.query", "query"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }

    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map(
            {{"server.request.query", "red-herring"}, {"server.request.body", "body"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    }
}

TEST(TestExpression, MatchWithKeyPath)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query", {"key"});
    builder.end_condition<matcher::regex_match>(".*", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map(
        {{"server.request.query", owned_object::make_map({{"key", "value"}})}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .highlight = "value",
                                .args = {{
                                    .value = "value",
                                    .address = "server.request.query",
                                    .path = {"key"},
                                }}});
}

TEST(TestExpression, MatchWithTransformer)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query", {}, {transformer_id::lowercase});
    builder.end_condition<matcher::regex_match>("value", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "VALUE"}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .highlight = "value",
                                .args = {{
                                    .value = "value",
                                    .address = "server.request.query",
                                }}});
}

TEST(TestExpression, MatchWithMultipleTransformers)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query", {},
        {transformer_id::compress_whitespace, transformer_id::lowercase});
    builder.end_condition<matcher::regex_match>("^ value $", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "    VALUE    "}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "^ value $",
                                .highlight = " value ",
                                .args = {{
                                    .value = " value ",
                                    .address = "server.request.query",
                                }}});
}

TEST(TestExpression, MatchOnKeys)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query", {}, {}, data_source::keys);
    builder.end_condition<matcher::regex_match>("value", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map(
        {{"server.request.query", owned_object::make_map({{"value", "1729"}})}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .highlight = "value",
                                .args = {{
                                    .value = "value",
                                    .address = "server.request.query",
                                    .path = {"value"},
                                }}});
}

TEST(TestExpression, MatchOnKeysWithTransformer)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query", {}, {transformer_id::lowercase}, data_source::keys);
    builder.end_condition<matcher::regex_match>("value", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map(
        {{"server.request.query", owned_object::make_map({{"VALUE", "1729"}})}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .highlight = "value",
                                .args = {{
                                    .value = "value",
                                    .address = "server.request.query",
                                    .path = {"VALUE"},
                                }}});
}

TEST(TestExpression, ExcludeInput)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>(".*", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map({{"server.request.query", "value"}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    std::unordered_set<object_view> excluded_objects{
        store.get_target("server.request.query").first};

    expression::cache_type cache;
    EXPECT_FALSE(expr->eval(cache, store, {excluded_objects, {}}, {}, deadline).outcome);
}

TEST(TestExpression, ExcludeKeyPath)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>(".*", 0, true);
    auto expr = builder.build();

    auto root = owned_object::make_map(
        {{"server.request.query", owned_object::make_map({{"key", "value"}})}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    std::unordered_set<object_view> excluded_objects{
        store.get_target("server.request.query").first};

    expression::cache_type cache;
    EXPECT_FALSE(expr->eval(cache, store, {excluded_objects, {}}, {}, deadline).outcome);
}
