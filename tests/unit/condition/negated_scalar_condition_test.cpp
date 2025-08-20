// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/negated_scalar_condition.hpp"
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

TEST(TestNegatedScalarCondition, VariadicTargetInConstructor)
{
    EXPECT_THROW((negated_scalar_condition{std::make_unique<matcher::regex_match>(".*", 0, true),
                     {}, {gen_variadic_param("server.request.uri.raw", "server.request.query")}}),
        std::invalid_argument);
}

TEST(TestNegatedScalarCondition, TooManyAddressesInConstructor)
{
    EXPECT_THROW(
        (negated_scalar_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {},
            {gen_variadic_param("server.request.uri.raw"),
                gen_variadic_param("server.request.query")}}),
        std::invalid_argument);
}

TEST(TestNegatedScalarCondition, NoAddressesInConstructor)
{
    EXPECT_THROW(
        (negated_scalar_condition{std::make_unique<matcher::regex_match>(".*", 0, true), {}, {}}),
        std::invalid_argument);
}

TEST(TestNegatedScalarCondition, NoMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", "hello"}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, Timeout)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", "hello"}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_THROW(cond.eval(cache, store, {}, {}, deadline), ddwaf::timeout_exception);
}

TEST(TestNegatedScalarCondition, SimpleMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", "bye"}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);

    // Ensure the resolved value is the single one that didn't match
    ASSERT_TRUE(cache.match.has_value());
    EXPECT_STR(cache.match->args[0].resolved, "bye");
    EXPECT_STR(cache.match->highlights[0], "bye");
}

TEST(TestNegatedScalarCondition, SimpleMatchWithKeyPath)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = get_target_index("server.request.uri.raw"),
            .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri.raw",
        object_builder::map(
            {{"path", object_builder::map({{"to", object_builder::map({{"object", "bye"}})}})}})}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);

    // Ensure the resolved value is the single one that didn't match
    ASSERT_TRUE(cache.match.has_value());
    EXPECT_STR(cache.match->args[0].resolved, "bye");
    EXPECT_EQ(cache.match->args[0].key_path.size(), 3);
    EXPECT_STR(cache.match->highlights[0], "bye");
}

TEST(TestNegatedScalarCondition, SingleValueArrayMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", object_builder::array({"bye"})}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);

    // Ensure the resolved value is the single one that didn't match
    ASSERT_TRUE(cache.match.has_value());
    EXPECT_STR(cache.match->args[0].resolved, "bye");
    EXPECT_EQ(cache.match->args[0].key_path.size(), 0);
    EXPECT_STR(cache.match->highlights[0], "bye");
}

TEST(TestNegatedScalarCondition, SingleValueArrayMatchWithKeyPath)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = get_target_index("server.request.uri.raw"),
            .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri.raw",
        object_builder::map({{"path",
            object_builder::map(
                {{"to", object_builder::map({{"object", object_builder::array({"bye"})}})}})}})}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);

    // Ensure the resolved value is the single one that didn't match
    ASSERT_TRUE(cache.match.has_value());
    EXPECT_STR(cache.match->args[0].resolved, "bye");
    EXPECT_EQ(cache.match->args[0].key_path.size(), 3);
    EXPECT_STR(cache.match->highlights[0], "bye");
}

TEST(TestNegatedScalarCondition, MultiValueArrayMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map(
        {{"server.request.uri.raw", object_builder::array({"bye", "greetings"})}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);

    // Ensure the resolved value is the single one that didn't match
    ASSERT_TRUE(cache.match.has_value());
    EXPECT_STR(cache.match->args[0].resolved, "");
    EXPECT_EQ(cache.match->args[0].key_path.size(), 0);
    EXPECT_TRUE(cache.match->highlights.empty());
}

TEST(TestNegatedScalarCondition, MultiValueArrayMatchWithKeyPath)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = get_target_index("server.request.uri.raw"),
            .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri.raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object",
                                            object_builder::array({"bye", "greetings"})}})}})}})}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);

    // Ensure the resolved value is the single one that didn't match
    ASSERT_TRUE(cache.match.has_value());
    EXPECT_STR(cache.match->args[0].resolved, "");
    EXPECT_EQ(cache.match->args[0].key_path.size(), 3);
    EXPECT_TRUE(cache.match->highlights.empty());
}

TEST(TestNegatedScalarCondition, ExcludedRootObject)
{
    auto target_index = get_target_index("server.request.uri.raw");
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = target_index,
            .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri.raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object",
                                            object_builder::array({"bye", "greetings"})}})}})}})}});

    object_store store;
    store.insert(root);

    std::unordered_set<object_view> excluded_objects;
    excluded_objects.emplace(store.get_target(target_index).first);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res =
        cond.eval(cache, store, {.persistent = excluded_objects, .ephemeral = {}}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, ExcludedIntermediateObject)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = get_target_index("server.request.uri.raw"),
            .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri.raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object",
                                            object_builder::array({"bye", "greetings"})}})}})}})}});

    std::vector<std::string> kp{"server.request.uri.raw", "path", "to"};

    std::unordered_set<object_view> excluded_objects;
    excluded_objects.emplace(object_view{root}.find_key_path(kp).at_value(0));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res =
        cond.eval(cache, store, {.persistent = excluded_objects, .ephemeral = {}}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, ExcludedFinalObject)
{
    auto target_index = get_target_index("server.request.uri.raw");
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = target_index,
            .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri.raw",
        object_builder::map({{"path",
            object_builder::map(
                {{"to", object_builder::map({{"object", object_builder::array({"bye"})}})}})}})}});

    std::vector<std::string> kp{"server.request.uri.raw", "path", "to", "object"};

    std::unordered_set<object_view> excluded_objects;
    excluded_objects.emplace(object_view{root}.find_key_path(kp).at_value(0));
    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res =
        cond.eval(cache, store, {.persistent = excluded_objects, .ephemeral = {}}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, CachedMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf::timer deadline{2s};
    condition_cache cache;

    auto root = object_builder::map({{"server.request.uri.raw", "bye"}});

    {
        object_store store;
        store.insert(root, object_store::attribute::none);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }

    {
        object_store store;
        store.insert(root, object_store::attribute::none);

        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }
}

TEST(TestNegatedScalarCondition, SimpleMatchOnKeys)
{
    auto target = gen_variadic_param("server.request.uri.raw");
    target.targets[0].source = data_source::keys;

    negated_scalar_condition cond{
        std::make_unique<matcher::regex_match>("hello", 0, true), {}, {std::move(target)}};

    auto root =
        object_builder::map({{"server.request.uri.raw", object_builder::map({{"bye", "hello"}})}});

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, SimpleEphemeralMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    auto root = object_builder::map({{"server.request.uri.raw", "bye"}});

    object_store store;
    {
        auto scope = store.get_eval_scope();

        store.insert(root, object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_TRUE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        store.insert(root, object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_TRUE(res.ephemeral);
    }
}

} // namespace
