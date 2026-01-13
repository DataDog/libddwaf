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
using namespace ddwaf::test;
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

    auto root = object_builder_da::map({{"server.request.uri.raw", owned_object{}}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestScalarCondition, Timeout)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder_da::map({{"server.request.uri.raw", owned_object{}}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_THROW(cond.eval(cache, store, {}, {}, deadline), ddwaf::timeout_exception);
}

TEST(TestScalarCondition, SimpleMatch)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder_da::map({{"server.request.uri.raw", "hello"}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestScalarCondition, CachedMatch)
{
    scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf::timer deadline{2s};
    condition_cache cache;

    auto root = object_builder_da::map({{"server.request.uri.raw", "hello"}});

    {
        object_store store;
        store.insert(root);

        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));
    }

    {
        object_store store;
        store.insert(root);

        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestScalarCondition, SimpleMatchOnKeys)
{
    auto param = gen_variadic_param("server.request.uri.raw");
    param.targets[0].source = data_source::keys;

    scalar_condition cond{
        std::make_unique<matcher::regex_match>(".*", 0, true), {}, {std::move(param)}};

    auto root = object_builder_da::map(
        {{"server.request.uri.raw", object_builder_da::map({{"hello", "hello"}})}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));
}

} // namespace
