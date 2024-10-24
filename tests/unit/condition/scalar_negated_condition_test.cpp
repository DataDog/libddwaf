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

TEST(TestScalarNegatedCondition, VariadicTargetInConstructor)
{
    EXPECT_THROW(
        (scalar_negated_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {},
            {gen_variadic_param("server.request.uri.raw", "server.request.query")}, {}}),
        std::invalid_argument);
}

TEST(TestScalarNegatedCondition, TooManyAddressesInConstructor)
{
    EXPECT_THROW(
        (scalar_negated_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {},
            {gen_variadic_param("server.request.uri.raw"),
                gen_variadic_param("server.request.query")},
            {}}),
        std::invalid_argument);
}

TEST(TestScalarNegatedCondition, NoAddressesInConstructor)
{
    EXPECT_THROW((scalar_negated_condition{
                     std::make_unique<matcher::regex_match>(".*", 0, true), {}, {}, {}}),
        std::invalid_argument);
}

TEST(TestScalarNegatedCondition, NoMatch)
{
    scalar_negated_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "hello"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestScalarNegatedCondition, Timeout)
{
    scalar_negated_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "hello"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_THROW(cond.eval(cache, store, {}, {}, deadline), ddwaf::timeout_exception);
}

TEST(TestScalarNegatedCondition, SimpleMatch)
{
    scalar_negated_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_invalid(&tmp));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestScalarNegatedCondition, CachedMatch)
{
    scalar_negated_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}, {}};

    ddwaf::timer deadline{2s};
    condition_cache cache;

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_invalid(&tmp));

    {
        object_store store;
        store.insert(root, object_store::attribute::none, nullptr);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }

    {
        object_store store;
        store.insert(root, object_store::attribute::none, nullptr);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }

    ddwaf_object_free(&root);
}

TEST(TestScalarNegatedCondition, SimpleMatchOnKeys)
{
    auto target = gen_variadic_param("server.request.uri.raw");
    target.targets[0].source = data_source::keys;

    scalar_negated_condition cond{
        std::make_unique<matcher::regex_match>("hello", 0, true), {}, {std::move(target)}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object map;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "bye", ddwaf_object_string(&tmp, "hello"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &map);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestScalarNegatedCondition, SimpleEphemeralMatch)
{
    scalar_negated_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_invalid(&tmp));

    object_store store;
    {
        auto scope = store.get_eval_scope();

        store.insert(root, object_store::attribute::ephemeral, nullptr);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_TRUE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        store.insert(root, object_store::attribute::ephemeral, nullptr);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_TRUE(res.ephemeral);
    }

    ddwaf_object_free(&root);
}

} // namespace
