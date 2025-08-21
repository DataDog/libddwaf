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

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "hello"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, NoMatchWithKeyPath)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = get_target_index("server.request.uri.raw"),
            .key_path = {"path", "to", "rome"}}}}}};

    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));

    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", &array);

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, Timeout)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>(".*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "hello"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_THROW(cond.eval(cache, store, {}, {}, {}, deadline), ddwaf::timeout_exception);
}

TEST(TestNegatedScalarCondition, SimpleMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "bye"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
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

    ddwaf_object tmp;
    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", ddwaf_object_string(&tmp, "bye"));

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
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

    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &array);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
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

    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));

    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", &array);

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
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

    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "greetings"));
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &array);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
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

    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "greetings"));

    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", &array);

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
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

    std::unordered_set<const ddwaf_object *> excluded_objects;

    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "greetings"));

    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", &array);

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    excluded_objects.emplace(store.get_target(target_index).first);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(
        cache, store, {.persistent = excluded_objects, .ephemeral = {}}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, ExcludedIntermediateObject)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {{{{.name = "server.request.uri.raw"s,
            .index = get_target_index("server.request.uri.raw"),
            .key_path = {"path", "to", "object"}}}}}};

    std::unordered_set<const ddwaf_object *> excluded_objects;

    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "greetings"));

    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", &array);

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    excluded_objects.emplace(&to.array[0]);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(
        cache, store, {.persistent = excluded_objects, .ephemeral = {}}, {}, {}, deadline);
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

    std::unordered_set<const ddwaf_object *> excluded_objects;

    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "bye"));

    excluded_objects.emplace(&array.array[0]);

    ddwaf_object object;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", &array);

    ddwaf_object to;
    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object path;
    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", &path);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(
        cache, store, {.persistent = excluded_objects, .ephemeral = {}}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, CachedMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf::timer deadline{2s};
    condition_cache cache;

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "bye"));

    {
        object_store store;
        store.insert(root, object_store::attribute::none, nullptr);

        auto res = cond.eval(cache, store, {}, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }

    {
        object_store store;
        store.insert(root, object_store::attribute::none, nullptr);

        auto res = cond.eval(cache, store, {}, {}, {}, deadline);
        ASSERT_FALSE(res.outcome);
        ASSERT_FALSE(res.ephemeral);
    }

    ddwaf_object_free(&root);
}

TEST(TestNegatedScalarCondition, SimpleMatchOnKeys)
{
    auto target = gen_variadic_param("server.request.uri.raw");
    target.targets[0].source = data_source::keys;

    negated_scalar_condition cond{
        std::make_unique<matcher::regex_match>("hello", 0, true), {}, {std::move(target)}};

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
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
    ASSERT_FALSE(res.ephemeral);
}

TEST(TestNegatedScalarCondition, SimpleEphemeralMatch)
{
    negated_scalar_condition cond{std::make_unique<matcher::regex_match>("hello.*", 0, true), {},
        {gen_variadic_param("server.request.uri.raw")}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri.raw", ddwaf_object_string(&tmp, "bye"));

    object_store store;
    {
        auto scope = store.get_eval_scope();

        store.insert(root, object_store::attribute::ephemeral, nullptr);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_TRUE(res.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();

        store.insert(root, object_store::attribute::ephemeral, nullptr);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, {}, deadline);
        ASSERT_TRUE(res.outcome);
        ASSERT_TRUE(res.ephemeral);
    }

    ddwaf_object_free(&root);
}

} // namespace
