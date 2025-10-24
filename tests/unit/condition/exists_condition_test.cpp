// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/exists.hpp"
#include "utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_variadic_param(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}...}}};
}

TEST(TestExistsCondition, AddressAvailable)
{
    exists_condition cond{{gen_variadic_param("server.request.uri_raw")}};

    auto root = object_builder::map({{"server.request.uri_raw", owned_object{}}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestExistsCondition, KeyPathAvailable)
{
    exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri_raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object", owned_object{}}})}})}})}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestExistsCondition, AddressNotAvaialble)
{
    exists_condition cond{{gen_variadic_param("server.request.uri_raw")}};

    auto root = object_builder::map({{"server.request.query", owned_object{}}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestExistsCondition, KeyPathNotAvailable)
{
    exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri_raw",
        object_builder::map({{"path", object_builder::map({{"to", owned_object{}}})}})}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestExistsCondition, KeyPathIndexOnNonArray)
{
    exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {0}}}}}};

    auto root = object_builder::map(
        {{"server.request.uri_raw", object_builder::map({{"path", owned_object{}}})}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestExistsCondition, KeyPathAvailableButExcluded)
{
    exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri_raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object", owned_object{}}})}})}})}});

    std::unordered_set<object_cache_key> excluded = {root.at(0)};
    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;

    // While the key path is present, since part of the path was excluded
    // the evaluation fails to determine the presence of the full key path,
    // for that reason, no match is generated.
    ASSERT_FALSE(cond.eval(cache, store, excluded, {}, deadline));
}

TEST(TestExistsCondition, MultipleAddresses)
{
    exists_condition cond{
        {gen_variadic_param("server.request.uri_raw", "server.request.body", "usr.id")}};

    auto validate_address = [&](const std::string &address, bool expected = true) {
        auto root = object_builder::map({{address, owned_object{}}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_EQ(cond.eval(cache, store, {}, {}, deadline), expected);
    };

    validate_address("usr.id");
    validate_address("server.request.body");
    validate_address("server.request.uri_raw");
    validate_address("server.request.query", false);
    validate_address("usr.session_id", false);
}

TEST(TestExistsCondition, MultipleAddressesAndKeyPaths)
{
    exists_condition cond{{{{{.name = "server.request.uri_raw",
                                 .index = get_target_index("server.request.uri_raw"),
                                 .key_path = {"path", "to", "object"}},
        {.name = "usr.id", .index = get_target_index("usr.id")},
        {.name = "server.request.body",
            .index = get_target_index("server.request.body"),
            .key_path = {"key"}}}}}};

    auto validate_address = [&](const std::string &address, const std::vector<std::string> &kp,
                                bool expected = true) {
        auto root = object_builder::map();
        auto map = root.emplace(address, object_builder::map());
        // NOLINTNEXTLINE(modernize-loop-convert)
        for (auto it = kp.begin(); it != kp.end(); ++it) {
            map = map.emplace(*it, object_builder::map());
        }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_EQ(cond.eval(cache, store, {}, {}, deadline), expected);
    };

    validate_address("usr.id", {});
    validate_address("usr.id", {"whatever"});
    validate_address("server.request.uri_raw", {"path", "to", "object"});
    validate_address("server.request.body", {"key"});
    validate_address("server.request.body", {}, false);
    validate_address("server.request.uri_raw", {"path", "to"}, false);
    validate_address("server.request.uri_raw", {"path"}, false);
    validate_address("server.request.uri_raw", {}, false);
    validate_address("server.request.query", {}, false);
    validate_address("usr.session_id", {}, false);
}

TEST(TestNegatedExistsCondition, KeyPathAvailable)
{
    negated_exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri_raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object", owned_object{}}})}})}})}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestNegatedExistsCondition, KeyPathNotAvailable)
{
    negated_exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri_raw",
        object_builder::map({{"path", object_builder::map({{"to", owned_object{}}})}})}});
    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestNegatedExistsCondition, KeyPathAvailableButExcluded)
{
    negated_exists_condition cond{{{{{.name = "server.request.uri_raw",
        .index = get_target_index("server.request.uri_raw"),
        .key_path = {"path", "to", "object"}}}}}};

    auto root = object_builder::map({{"server.request.uri_raw",
        object_builder::map({{"path",
            object_builder::map({{"to", object_builder::map({{"object", owned_object{}}})}})}})}});

    std::unordered_set<object_cache_key> excluded = {root.at(0)};

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;

    // While the key path is not present, since part of the path was excluded
    // the evaluation fails to determine the presence of the full key path,
    // for that reason, no match is generated.
    ASSERT_FALSE(cond.eval(cache, store, excluded, {}, deadline));
}

} // namespace
