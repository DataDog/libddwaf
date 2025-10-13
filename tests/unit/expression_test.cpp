// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "expression.hpp"
#include "matcher/regex_match.hpp"
#include "object_store.hpp"
#include "utils.hpp"

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

    auto root = object_builder::map({{"server.request.query", "value"}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    auto res = expr->eval(cache, store, {}, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());

    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_EQ(matches.size(), 1);
    EXPECT_TRUE(matches[0].scope.is_context());
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .highlight = "value"sv,
                                .args = {{
                                    .value = "value"sv,
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

    auto root = object_builder::map({{"server.request.query", "val"}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    auto res = expr->eval(cache, store, {}, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());

    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_EQ(matches.size(), 1);
    EXPECT_TRUE(matches[0].scope.is_context());
    EXPECT_MATCHES(matches, {.op = "!match_regex",
                                .op_value = ".*",
                                .highlight = "val"sv,
                                .args = {{
                                    .value = "val"sv,
                                    .address = "server.request.query",
                                }}});
}

TEST(TestExpression, SubcontextMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>(".*", 0, true);

    auto expr = builder.build();

    auto root = object_builder::map({{"server.request.query", "value"}});

    subcontext_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_subcontext());

    auto matches = ddwaf::expression::get_matches(cache, evaluation_scope::subcontext());
    EXPECT_EQ(matches.size(), 1);
    EXPECT_TRUE(matches[0].scope.is_subcontext());
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .highlight = "value"sv,
                                .args = {{
                                    .value = "value"sv,
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

    context_object_store store;
    expression::cache_type cache;

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "bad"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.body", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());

        auto matches = ddwaf::expression::get_matches(cache);
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .highlight = "value"sv,
                                    .args = {{
                                        .value = "value"sv,
                                        .address = "server.request.body",
                                    }}});
    }
}

TEST(TestExpression, SubcontextMatchOnSecondEval)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.body");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    expression::cache_type cache;

    {
        auto root = object_builder::map({{"server.request.body", "bad"}});

        subcontext_object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }

    {
        auto root = object_builder::map({{"server.request.body", "value"}});

        subcontext_object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_subcontext());

        auto matches = ddwaf::expression::get_matches(cache, evaluation_scope::subcontext());
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .highlight = "value"sv,
                                    .args = {{
                                        .value = "value"sv,
                                        .address = "server.request.body",
                                    }}});
    }
}

TEST(TestExpression, SubcontextMatchTwoConditions)
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

    subcontext_object_store store;
    expression::cache_type cache;

    {
        auto root = object_builder::map({{"server.request.body", "value"}});
        store.insert(std::move(root));
    }

    {
        auto root = object_builder::map({{"server.request.query", "value"}});
        store.insert(std::move(root));
    }

    ddwaf::timer deadline{2s};

    auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_subcontext());

    auto matches = ddwaf::expression::get_matches(cache, evaluation_scope::subcontext());
    EXPECT_MATCHES(matches,
        {.op = "match_regex",
            .op_value = "^value$",
            .highlight = "value"sv,
            .args = {{
                .value = "value"sv,
                .address = "server.request.query",
            }}},
        {.op = "match_regex",
            .op_value = "^value$",
            .highlight = "value"sv,
            .args = {{
                .value = "value"sv,
                .address = "server.request.body",
            }}});
}

TEST(TestExpression, SubcontextMatchOnFirstConditionFirstEval)
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

    expression::cache_type cache;

    {
        auto root = object_builder::map({{"server.request.query", "value"}});

        subcontext_object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_FALSE(res.outcome);
    }

    {
        auto root = object_builder::map({{"server.request.body", "value"}});

        context_object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
    }
}

TEST(TestExpression, SubcontextMatchOnFirstConditionSecondEval)
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

    context_object_store ctx_store;
    expression::cache_type cache;

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.body", "value"}});

        ctx_store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, ctx_store, {}, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }

    {
        subcontext_object_store sctx_store{ctx_store};
        auto root = object_builder::map({{"server.request.query", "value"}});

        sctx_store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, sctx_store, {}, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_subcontext());
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
    context_object_store store;

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "bad"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }
}

TEST(TestExpression, DuplicateSubcontextInput)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>("^value$", 0, true);

    auto expr = builder.build();

    expression::cache_type cache;
    {
        auto root = object_builder::map({{"server.request.query", "value"}});
        subcontext_object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_subcontext());
    }

    {
        auto root = object_builder::map({{"server.request.query", "value"}});

        subcontext_object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        auto res = expr->eval(cache, store, {}, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_subcontext());
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

    context_object_store store;
    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "bad"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_FALSE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        expression::cache_type cache;
        EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);

        auto matches = ddwaf::expression::get_matches(cache);
        EXPECT_EQ(matches.size(), 1);
        EXPECT_TRUE(matches[0].scope.is_context());
        EXPECT_MATCHES(matches, {.op = "match_regex",
                                    .op_value = "^value$",
                                    .highlight = "value"sv,
                                    .args = {{
                                        .value = "value"sv,
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
    context_object_store store;

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "bad_value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "value"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
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

    auto root = object_builder::map({{"server.request.query", "value"}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
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

    context_object_store store;
    expression::cache_type cache;

    auto root =
        object_builder::map({{"server.request.query", "query"}, {"server.request.body", "body"}});

    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
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

    context_object_store store;
    expression::cache_type cache;

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map({{"server.request.query", "query"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_FALSE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        auto root = object_builder::map(
            {{"server.request.query", "red-herring"}, {"server.request.body", "body"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};

        EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
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

    auto root =
        object_builder::map({{"server.request.query", object_builder::map({{"key", "value"}})}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = ".*",
                                .highlight = "value"sv,
                                .args = {{
                                    .value = "value"sv,
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

    auto root = object_builder::map({{"server.request.query", "VALUE"}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .highlight = "value"sv,
                                .args = {{
                                    .value = "value"sv,
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

    auto root = object_builder::map({{"server.request.query", "    VALUE    "}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "^ value $",
                                .highlight = " value "sv,
                                .args = {{
                                    .value = " value "sv,
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

    auto root =
        object_builder::map({{"server.request.query", object_builder::map({{"value", "1729"}})}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .highlight = "value"sv,
                                .args = {{
                                    .value = "value"sv,
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

    auto root =
        object_builder::map({{"server.request.query", object_builder::map({{"VALUE", "1729"}})}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    expression::cache_type cache;
    EXPECT_TRUE(expr->eval(cache, store, {}, {}, {}, deadline).outcome);
    auto matches = ddwaf::expression::get_matches(cache);
    EXPECT_MATCHES(matches, {.op = "match_regex",
                                .op_value = "value",
                                .highlight = "value"sv,
                                .args = {{
                                    .value = "value"sv,
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

    auto root = object_builder::map({{"server.request.query", "value"}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    std::unordered_set<object_cache_key> excluded_objects{
        store.get_target("server.request.query").first};

    expression::cache_type cache;
    EXPECT_FALSE(expr->eval(cache, store, {excluded_objects, {}}, {}, {}, deadline).outcome);
}

TEST(TestExpression, ExcludeKeyPath)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("server.request.query");
    builder.end_condition<matcher::regex_match>(".*", 0, true);
    auto expr = builder.build();

    auto root =
        object_builder::map({{"server.request.query", object_builder::map({{"key", "value"}})}});

    context_object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    std::unordered_set<object_cache_key> excluded_objects{
        store.get_target("server.request.query").first};

    expression::cache_type cache;
    EXPECT_FALSE(expr->eval(cache, store, {excluded_objects, {}}, {}, {}, deadline).outcome);
}
