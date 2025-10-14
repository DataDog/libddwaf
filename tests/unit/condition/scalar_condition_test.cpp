// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/scalar_condition.hpp"
#include "exception.hpp"
#include "matcher/regex_match.hpp"
#include "utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> condition_parameter gen_variadic_param(Args... addresses)
{
    return {{{std::string{addresses}, get_target_index(addresses)}...}};
}

TEST(TestScalarCondition, TooManyAddressesInConstructor)
{
    EXPECT_THROW((scalar_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {},
                     {gen_variadic_param("server.request.uri.raw"),
                         gen_variadic_param("server.request.query")}}),
        std::invalid_argument);
}

TEST(TestScalarCondition, NoAddressesInConstructor)
{
    EXPECT_THROW((scalar_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {}, {}}),
        std::invalid_argument);
}

TEST(TestScalarCondition, NoMatch)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", owned_object{}}});

    auto store = object_store::make_context_store();
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
}

TEST(TestScalarCondition, Timeout)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", owned_object{}}});

    auto store = object_store::make_context_store();
    store.insert(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_THROW(cond.eval(cache, store, {}, {}, deadline), ddwaf::timeout_exception);
}

TEST(TestScalarCondition, SimpleMatch)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", "hello"}});

    auto store = object_store::make_context_store();
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
}

TEST(TestScalarCondition, CachedMatch)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf::timer deadline{2s};
    condition_cache cache;

    auto root = object_builder::map({{"server.request.uri.raw", "hello"}});

    {
        auto store = object_store::make_context_store();
        store.insert(root);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }

    {
        auto store = object_store::make_context_store();
        store.insert(root);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());
    }
}

TEST(TestScalarCondition, SimpleMatchOnKeys)
{
    auto param = gen_variadic_param("server.request.uri.raw");
    param.targets[0].source = data_source::keys;

    scalar_condition cond{
        std::make_unique<matcher::regex_match>(".*", 0, true), {}, {std::move(param)}};

    auto root = object_builder::map(
        {{"server.request.uri.raw", object_builder::map({{"hello", "hello"}})}});

    auto store = object_store::make_context_store();
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
}

TEST(TestScalarCondition, SimpleSubcontextMatch)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", "hello"}});

    auto ctx_store = object_store::make_context_store();
    {
        auto sctx_store = object_store::make_subcontext_store(ctx_store);
        sctx_store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, sctx_store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_subcontext());
    }

    {
        auto sctx_store = object_store::make_subcontext_store(ctx_store);
        sctx_store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, sctx_store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_subcontext());
    }
}

} // namespace
