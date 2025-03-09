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

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", ddwaf_object_invalid(&tmp));

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
}

TEST(TestExistsCondition, KeyPathAvailable)
{
    exists_condition cond{{{{{{"server.request.uri_raw", get_target_index("server.request.uri_raw"),
        {"path", "to", "object"}}}}}}};

    ddwaf_object tmp;
    ddwaf_object path;
    ddwaf_object to;
    ddwaf_object object;

    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", ddwaf_object_invalid(&tmp));

    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", &path);

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
}

TEST(TestExistsCondition, AddressNotAvaialble)
{
    exists_condition cond{{gen_variadic_param("server.request.uri_raw")}};

    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_invalid(&tmp));

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestExistsCondition, KeyPathNotAvailable)
{
    exists_condition cond{{{{{{"server.request.uri_raw", get_target_index("server.request.uri_raw"),
        {"path", "to", "object"}}}}}}};

    ddwaf_object tmp;
    ddwaf_object path;
    ddwaf_object to;

    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", ddwaf_object_invalid(&tmp));

    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", &path);

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestExistsCondition, KeyPathAvailableButExcluded)
{
    exists_condition cond{{{{{{"server.request.uri_raw", get_target_index("server.request.uri_raw"),
        {"path", "to", "object"}}}}}}};

    ddwaf_object tmp;
    ddwaf_object path;
    ddwaf_object to;
    ddwaf_object object;

    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", ddwaf_object_invalid(&tmp));

    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", &path);

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;

    std::unordered_set<object_view> excluded = {&root.array[0]};

    exclusion::object_set_ref excluded_ref;
    excluded_ref.persistent = excluded;

    // While the key path is present, since part of the path was excluded
    // the evaluation fails to determine the presence of the full key path,
    // for that reason, no match is generated.
    auto res = cond.eval(cache, store, excluded_ref, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestExistsCondition, MultipleAddresses)
{
    exists_condition cond{
        {gen_variadic_param("server.request.uri_raw", "server.request.body", "usr.id")}};

    auto validate_address = [&](const std::string &address, bool expected = true) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, address.c_str(), ddwaf_object_invalid(&tmp));

        object_store store;
        store.insert(owned_object{root});

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, {}, deadline);
        ASSERT_EQ(res.outcome, expected);
    };

    validate_address("usr.id");
    validate_address("server.request.body");
    validate_address("server.request.uri_raw");
    validate_address("server.request.query", false);
    validate_address("usr.session_id", false);
}

TEST(TestExistsCondition, MultipleAddressesAndKeyPaths)
{
    exists_condition cond{{{{{"server.request.uri_raw", get_target_index("server.request.uri_raw"),
                                 {"path", "to", "object"}},
        {"usr.id", get_target_index("usr.id")},
        {"server.request.body", get_target_index("server.request.body"), {"key"}}}}}};

    auto validate_address = [&](const std::string &address, const std::vector<std::string> &kp,
                                bool expected = true) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);
        ddwaf_object_invalid(&tmp);

        // NOLINTNEXTLINE(modernize-loop-convert)
        for (auto it = kp.rbegin(); it != kp.rend(); ++it) {
            ddwaf_object path;
            ddwaf_object_map(&path);
            ddwaf_object_map_add(&path, it->c_str(), &tmp);

            tmp = path;
        }

        ddwaf_object_map_add(&root, address.c_str(), &tmp);

        object_store store;
        store.insert(owned_object{root});

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, {}, deadline);
        ASSERT_EQ(res.outcome, expected);
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

TEST(TestExistsNegatedCondition, KeyPathAvailable)
{
    exists_negated_condition cond{{{{{{"server.request.uri_raw",
        get_target_index("server.request.uri_raw"), {"path", "to", "object"}}}}}}};

    ddwaf_object tmp;
    ddwaf_object path;
    ddwaf_object to;
    ddwaf_object object;

    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "object", ddwaf_object_invalid(&tmp));

    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", &object);

    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", &path);

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestExistsNegatedCondition, KeyPathNotAvailable)
{
    exists_negated_condition cond{{{{{{"server.request.uri_raw",
        get_target_index("server.request.uri_raw"), {"path", "to", "object"}}}}}}};

    ddwaf_object tmp;
    ddwaf_object path;
    ddwaf_object to;

    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", ddwaf_object_invalid(&tmp));

    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", &path);

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, {}, deadline);
    ASSERT_TRUE(res.outcome);
}

TEST(TestExistsNegatedCondition, KeyPathAvailableButExcluded)
{
    exists_negated_condition cond{{{{{{"server.request.uri_raw",
        get_target_index("server.request.uri_raw"), {"path", "to", "object"}}}}}}};

    ddwaf_object tmp;
    ddwaf_object path;
    ddwaf_object to;

    ddwaf_object_map(&to);
    ddwaf_object_map_add(&to, "to", ddwaf_object_invalid(&tmp));

    ddwaf_object_map(&path);
    ddwaf_object_map_add(&path, "path", &to);

    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.uri_raw", &path);

    object_store store;
    store.insert(owned_object{root});

    ddwaf::timer deadline{2s};
    condition_cache cache;

    std::unordered_set<object_view> excluded = {&root.array[0]};

    exclusion::object_set_ref excluded_ref;
    excluded_ref.persistent = excluded;

    // While the key path is not present, since part of the path was excluded
    // the evaluation fails to determine the presence of the full key path,
    // for that reason, no match is generated.
    auto res = cond.eval(cache, store, excluded_ref, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

} // namespace
