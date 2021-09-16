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

    manifest.insert("path", PWManifest::ArgDetails("path"));

    EXPECT_TRUE(manifest.hasTarget("path"));
    EXPECT_FALSE(manifest.empty());

    auto id  = manifest.getTargetArgID("path");
    auto str = manifest.getTargetName(id);

    EXPECT_STREQ(str.c_str(), "path");

    auto& details = manifest.getDetailsForTarget(id);
    EXPECT_TRUE(details.runOnValue);
    EXPECT_FALSE(details.runOnKey);
    EXPECT_TRUE(details.keyPaths.empty());
    EXPECT_STREQ(details.inheritFrom.c_str(), "path");

    std::unordered_set<std::string> newFields { "path" };
    std::unordered_set<PWManifest::ARG_ID> argsImpacted;

    manifest.findImpactedArgs(newFields, argsImpacted);
    EXPECT_EQ(argsImpacted.size(), 1);
    EXPECT_NE(argsImpacted.find(id), argsImpacted.end());
}

TEST(TestPWManifest, TestMultipleAddrs)
{
    PWManifest manifest;

    for (auto str : { "path0", "path1", "path2", "path3" })
    {
        manifest.insert(str, PWManifest::ArgDetails(str));
        EXPECT_TRUE(manifest.hasTarget(str));

        auto id = manifest.getTargetArgID(str);

        auto& details = manifest.getDetailsForTarget(id);
        EXPECT_TRUE(details.runOnValue);
        EXPECT_FALSE(details.runOnKey);
        EXPECT_TRUE(details.keyPaths.empty());
        EXPECT_STREQ(details.inheritFrom.c_str(), str);

        std::unordered_set<std::string> newFields { str };
        std::unordered_set<PWManifest::ARG_ID> argsImpacted;

        manifest.findImpactedArgs(newFields, argsImpacted);
        EXPECT_EQ(argsImpacted.size(), 1);
        EXPECT_NE(argsImpacted.find(id), argsImpacted.end());
    }
}

TEST(TestPWManifest, TestKeyPaths)
{
    PWManifest manifest;

    std::vector<std::string> paths { "path:x-key-0", "path:x-key-1",
                                     "path:x-key-2", "path:x-key-3" };

    manifest.insert("path", PWManifest::ArgDetails("path"));

    for (auto& str : paths)
    {
        manifest.insert(str, PWManifest::ArgDetails(str));
    }

    for (const std::string& str : paths)
    {
        auto id = manifest.getTargetArgID(str);

        size_t end = str.find(':', 0);

        auto main = str.substr(0, end);
        auto key  = str.substr(end + 1, str.size());

        auto& details = manifest.getDetailsForTarget(id);
        EXPECT_TRUE(details.runOnValue);
        EXPECT_FALSE(details.runOnKey);
        EXPECT_EQ(details.keyPaths.size(), 1);
        EXPECT_STREQ(details.keyPaths[0].c_str(), key.c_str());
        EXPECT_STREQ(details.inheritFrom.c_str(), main.c_str());

        std::unordered_set<std::string> newFields { main };
        std::unordered_set<PWManifest::ARG_ID> argsImpacted;

        manifest.findImpactedArgs(newFields, argsImpacted);
        EXPECT_EQ(argsImpacted.size(), 5);
        EXPECT_NE(argsImpacted.find(id), argsImpacted.end());
    }
}

TEST(TestPWManifest, TestUnknownArgID)
{
    PWManifest manifest;
    EXPECT_STREQ(manifest.getTargetName(1729).c_str(), "<invalid>");
}
