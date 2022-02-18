// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestPWManifest, TestBasic)
{
    PWManifest manifest;
    EXPECT_FALSE(manifest.hasTarget("path"));
    EXPECT_TRUE(manifest.empty());

    manifest.insert("path", PWManifest::ArgDetails("path", PWT_VALUES_ONLY));

	EXPECT_TRUE(manifest.hasTarget("path", PWT_VALUES_ONLY));
	EXPECT_FALSE(manifest.hasTarget("path", PWT_KEYS_ONLY));
	EXPECT_FALSE(manifest.empty());

    auto id  = manifest.getTargetArgID("path");
    auto str = manifest.getTargetName(id);

    EXPECT_STREQ(str.c_str(), "path");

    auto& details = manifest.getDetailsForTarget(id);
    EXPECT_TRUE(details.inline_transformer & PWT_VALUES_ONLY);
    EXPECT_FALSE(details.inline_transformer & PWT_KEYS_ONLY);
    EXPECT_TRUE(details.keyPaths.empty());
    EXPECT_STREQ(details.inheritFrom.c_str(), "path");

    std::unordered_set<std::string> newFields { "path" };
    std::unordered_set<PWManifest::ARG_ID> argsImpacted;

    manifest.findImpactedArgs(newFields, argsImpacted);
    EXPECT_EQ(argsImpacted.size(), 1);
    EXPECT_NE(argsImpacted.find(id), argsImpacted.end());

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses[0], "path");
}

TEST(TestPWManifest, TestMultipleAddrs)
{
    PWManifest manifest;

    for (auto str : { "path0", "path1", "path2", "path3" })
    {
        manifest.insert(str, PWManifest::ArgDetails(str, PWT_VALUES_ONLY));
        EXPECT_TRUE(manifest.hasTarget(str));

        auto id = manifest.getTargetArgID(str);

        auto& details = manifest.getDetailsForTarget(id);
        EXPECT_TRUE(details.inline_transformer & PWT_VALUES_ONLY);
        EXPECT_FALSE(details.inline_transformer & PWT_KEYS_ONLY);
        EXPECT_TRUE(details.keyPaths.empty());
        EXPECT_STREQ(details.inheritFrom.c_str(), str);

        std::unordered_set<std::string> newFields { str };
        std::unordered_set<PWManifest::ARG_ID> argsImpacted;

        manifest.findImpactedArgs(newFields, argsImpacted);
        EXPECT_EQ(argsImpacted.size(), 1);
        EXPECT_NE(argsImpacted.find(id), argsImpacted.end());
    }

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);
    EXPECT_STREQ(addresses[0], "path0");
    EXPECT_STREQ(addresses[1], "path1");
    EXPECT_STREQ(addresses[2], "path2");
    EXPECT_STREQ(addresses[3], "path3");
}

TEST(TestPWManifest, TestMultipleAddrsKeyPath)
{
    PWManifest manifest;

    for (auto str : { "path0", "path1", "path2", "path3" })
    {
		manifest.insert(str, PWManifest::ArgDetails(str, "key_path", PWT_VALUES_ONLY));
        EXPECT_TRUE(manifest.hasTarget(str));

        auto id = manifest.getTargetArgID(str);

        auto& details = manifest.getDetailsForTarget(id);
        EXPECT_TRUE(details.inline_transformer & PWT_VALUES_ONLY);
        EXPECT_FALSE(details.inline_transformer & PWT_KEYS_ONLY);
        EXPECT_EQ(details.keyPaths.size(), 1);
        EXPECT_STREQ(details.inheritFrom.c_str(), str);

        std::unordered_set<std::string> newFields { str };
        std::unordered_set<PWManifest::ARG_ID> argsImpacted;

        manifest.findImpactedArgs(newFields, argsImpacted);
        EXPECT_EQ(argsImpacted.size(), 1);
        EXPECT_NE(argsImpacted.find(id), argsImpacted.end());
    }

    auto& addresses = manifest.get_root_addresses();
    EXPECT_EQ(addresses.size(), 4);
    EXPECT_STREQ(addresses[0], "path0");
    EXPECT_STREQ(addresses[1], "path1");
    EXPECT_STREQ(addresses[2], "path2");
    EXPECT_STREQ(addresses[3], "path3");
}

TEST(TestPWManifest, TestUnknownArgID)
{
    PWManifest manifest;
    EXPECT_STREQ(manifest.getTargetName(1729).c_str(), "<invalid>");
}
