// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "condition/exists.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST(TestExistsCondition, AddressAvailable)
{
    exists_condition cond{{gen_param_def("server.request.uri_raw")}};

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
    exists_condition cond{{gen_param_def("server.request.uri_raw")}};

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

} // namespace
