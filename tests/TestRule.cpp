// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestCondition, TestMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("server.request.query", {}));

    auto manifest = mb.build_manifest();

    condition cond(std::move(targets), {},
        std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));


    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    EXPECT_TRUE(cond.match(store, manifest, true, deadline).has_value());
}
