// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "condition/scalar_condition.hpp"
#include "matcher/regex_match.hpp"
#include "utils.hpp"

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
            {gen_variadic_param("server.request.uri_raw", "server.request.query")}, {}}),
        std::invalid_argument);
}

TEST(TestScalarNegatedCondition, TooManyAddressesInConstructor)
{
    EXPECT_THROW(
        (scalar_negated_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {},
            {gen_variadic_param("server.request.uri_raw"),
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
        {gen_variadic_param("server.request.uri_raw")}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", ddwaf_object_string(&tmp, "hello"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestScalarNegatedCondition, SimpleMatch)
{
    scalar_negated_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri_raw")}, {}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", ddwaf_object_invalid(&tmp));

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
        {gen_variadic_param("server.request.uri_raw")}, {}};

    ddwaf::timer deadline{2s};
    condition_cache cache;

    ddwaf_object tmp;
    ddwaf_object root;

    {
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.uri_raw", ddwaf_object_invalid(&tmp));

        object_store store;
        store.insert(root);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }

    {
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.uri_raw", ddwaf_object_invalid(&tmp));

        object_store store;
        store.insert(root);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }
}

} // namespace
