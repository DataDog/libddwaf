// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestManifest, TestEmpty)
{
    auto manifest = ddwaf::manifest_builder().generate_manifest();
    EXPECT_FALSE(manifest.contains("path"));
    EXPECT_TRUE(manifest.empty());
}

TEST(TestManifest, TestBasic)
{
    ddwaf::manifest_builder mb;
    mb.insert("path", {});

    auto manifest = mb.generate_manifest();

    EXPECT_TRUE(manifest.contains("path"));
    EXPECT_FALSE(manifest.empty());

    auto id  = manifest.get_target("path");
    auto info = manifest.get_target_info(id);
    EXPECT_TRUE(info.key_path.empty());
    EXPECT_STREQ(info.name.c_str(), "path");

    // This is it's own root address
    EXPECT_EQ(id.root(), id);

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses[0], "path");
}

TEST(TestManifest, TestMultipleAddrs)
{
    ddwaf::manifest_builder mb;

    for (auto str : { "path0", "path1", "path2", "path3" })
    {
        mb.insert(str, {});
    }

    auto manifest = mb.generate_manifest();

    for (auto str : { "path0", "path1", "path2", "path3" })
    {
        EXPECT_TRUE(manifest.contains(str));

        auto id = manifest.get_target(str);
        auto info = manifest.get_target_info(id);
        EXPECT_TRUE(info.key_path.empty());
        // This is it's own root address
        EXPECT_EQ(id.root(), id);
    }

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);

    for (const std::string &str : {"path0", "path1", "path2", "path3"}) {
        EXPECT_NE(find(addresses.begin(), addresses.end(), str), addresses.end());
    }
}

TEST(TestManifest, TestMultipleAddrsKeyPath)
{
    ddwaf::manifest_builder mb;
    std::map<std::string, manifest::target_type> targets;
    for (auto str : { "path0", "path1", "path2", "path3" })
    {
        targets.emplace(str, mb.insert(str, {"key_path"}));
    }

    auto manifest = mb.generate_manifest();

    for (auto &[name, id] : targets)
    {
        auto root_id = manifest.get_target(name);
        auto info = manifest.get_target_info(id);
        EXPECT_EQ(info.key_path.size(), 1);
        EXPECT_EQ(id.root(), root_id);
        EXPECT_STREQ(info.name.c_str(), name.c_str());
    }

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);
    for (const std::string &str : {"path0", "path1", "path2", "path3"}) {
        EXPECT_NE(find(addresses.begin(), addresses.end(), str), addresses.end());
    }
}

TEST(TestManifest, TestUnknownArgID)
{
    ddwaf::manifest manifest({}, {});
    EXPECT_FALSE(manifest.contains({}));
}
