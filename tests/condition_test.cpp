// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestCondition, Match)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("server.request.query", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, manifest, {}, true, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), ".*");
    EXPECT_STREQ(match->source.data(), "server.request.query");
    EXPECT_TRUE(match->key_path.empty());
}

TEST(TestCondition, NoMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{}));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, manifest, {}, true, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestCondition, ExcludeInput)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("server.request.query", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, manifest, {&root.array[0]}, true, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestCondition, ExcludeKeyPath)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("server.request.query", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root, map, tmp;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &map);

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, manifest, {&map.array[0]}, true, deadline);
    EXPECT_FALSE(match.has_value());
}
