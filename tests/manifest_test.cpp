// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestManifest, TestBasic)
{
    ddwaf::manifest manifest;
    EXPECT_FALSE(manifest.contains("path"));
    EXPECT_TRUE(manifest.empty());

    manifest.insert("path", "path");

    EXPECT_TRUE(manifest.contains("path"));
    EXPECT_FALSE(manifest.empty());

    auto id  = manifest.get_target("path");
    auto str = manifest.get_target_name(id);

    EXPECT_STREQ(str.c_str(), "path");

    auto info = manifest.get_target_info(id);
    EXPECT_TRUE(info.key_path.empty());
    // This is it's own root address
    EXPECT_EQ(info.root, id);

    ddwaf::manifest::target_set new_targets = {id};
    ddwaf::manifest::target_set derived_targets;

    manifest.find_derived_targets(new_targets, derived_targets);
    EXPECT_EQ(derived_targets.size(), 1);
    EXPECT_NE(derived_targets.find(id), derived_targets.end());

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses[0], "path");
}

TEST(TestManifest, TestMultipleAddrs)
{
    ddwaf::manifest manifest;

    for (auto str : { "path0", "path1", "path2", "path3" })
    {
        manifest.insert(str, str);
        EXPECT_TRUE(manifest.contains(str));

        auto id = manifest.get_target(str);

        auto info = manifest.get_target_info(id);
        EXPECT_TRUE(info.key_path.empty());
        // This is it's own root address
        EXPECT_EQ(info.root, id);

        ddwaf::manifest::target_set new_targets = {id};
        ddwaf::manifest::target_set derived_targets;

        manifest.find_derived_targets(new_targets, derived_targets);
        EXPECT_EQ(derived_targets.size(), 1);
        EXPECT_NE(derived_targets.find(id), derived_targets.end());
    }

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);

    for (const std::string &str : {"path0", "path1", "path2", "path3"}) {
        EXPECT_NE(find(addresses.begin(), addresses.end(), str), addresses.end());
    }
}

TEST(TestManifest, TestMultipleAddrsKeyPath)
{
    ddwaf::manifest manifest;

    for (const std::string &str : {"path0", "path1", "path2", "path3"})
    {
        std::string new_str = str + ":key_path";
        auto id = manifest.insert(new_str, str, "key_path");
        auto root_id = manifest.get_target(str);

        EXPECT_TRUE(manifest.contains(new_str));
        EXPECT_TRUE(manifest.contains(str));

        auto info = manifest.get_target_info(id);
        EXPECT_EQ(info.key_path.size(), 1);
        EXPECT_EQ(info.root, root_id);

        ddwaf::manifest::target_set new_targets = {root_id};
        ddwaf::manifest::target_set derived_targets;

        manifest.find_derived_targets(new_targets, derived_targets);
        EXPECT_EQ(derived_targets.size(), 1);
        EXPECT_NE(derived_targets.find(id), derived_targets.end());
    }

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);
    for (const std::string &str : {"path0", "path1", "path2", "path3"}) {
        EXPECT_NE(find(addresses.begin(), addresses.end(), str), addresses.end());
    }
}

TEST(TestManifest, TestUnknownArgID)
{
    ddwaf::manifest manifest;
    EXPECT_TRUE(manifest.get_target_name(1729).empty());
}
