// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "condition/exists.hpp"
#include "utils.hpp"

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
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
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
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
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
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_EQ(res.outcome, expected);
    };

    validate_address("usr.id");
    validate_address("server.request.body");
    validate_address("server.request.uri_raw");
    validate_address("server.request.query", false);
    validate_address("usr.session_id", false);
}

} // namespace
