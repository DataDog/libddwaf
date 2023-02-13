// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestManifest, TestEmpty)
{
    ddwaf::manifest manifest;
    auto opt_target = manifest.find("path");
    EXPECT_FALSE(opt_target);
}

TEST(TestManifest, TestBasic)
{
    ddwaf::manifest manifest;
    auto target = manifest.insert("path");

    {
        auto opt_target = manifest.find("path");
        EXPECT_TRUE(opt_target.has_value());
        EXPECT_EQ(*opt_target, target);
    }

    // Test double insertion
    EXPECT_EQ(target, manifest.insert("path"));

    const auto &addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses[0], "path");
}

TEST(TestManifest, TestMultipleAddrs)
{
    ddwaf::manifest manifest;

    std::map<std::string, manifest::target_type> targets;
    for (const std::string str : {"path0", "path1", "path2", "path3"}) {
        auto target = manifest.insert(str);
        targets[str] = target;

        // Test double insertion
        EXPECT_EQ(target, manifest.insert(str));

        auto opt_target = manifest.find(str);
        EXPECT_TRUE(opt_target.has_value());
        EXPECT_EQ(*opt_target, target);
    }

    const auto &addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);

    for (const std::string str : {"path0", "path1", "path2", "path3"}) {
        EXPECT_NE(find(addresses.begin(), addresses.end(), str), addresses.end());
    }
}
