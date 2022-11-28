// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"
#include <gtest/gtest.h>

TEST(TestPathTrie, Basic)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "to", "object"});
    trie.insert<std::string_view>({"path", "to", "another", "object"});

    {
        auto path = trie.find("path");
        EXPECT_TRUE(path.is_valid());
        EXPECT_FALSE(path.is_terminal());

        auto to = path.find("to");
        EXPECT_TRUE(to.is_valid());
        EXPECT_FALSE(to.is_terminal());

        auto object = to.find("object");
        EXPECT_FALSE(object.is_valid());
        EXPECT_TRUE(object.is_terminal());
    }

    {
        auto subtrie = trie.find<std::string_view>({"path", "to", "another", "object"});
        EXPECT_FALSE(subtrie.is_valid());
        EXPECT_TRUE(subtrie.is_terminal());
    }

    trie.insert<std::string>({"path", "to"});
    {
        auto path = trie.find("path");
        EXPECT_TRUE(path.is_valid());
        EXPECT_FALSE(path.is_terminal());

        auto to = path.find("to");
        EXPECT_TRUE(to.is_valid());
        EXPECT_TRUE(to.is_terminal());

        auto object = to.find("object");
        EXPECT_FALSE(object.is_valid());
        EXPECT_TRUE(object.is_terminal());
    }

    {
        auto path = trie.find("path");
        EXPECT_TRUE(path.is_valid());
        EXPECT_FALSE(path.is_terminal());

        auto to = path.find("to");
        EXPECT_TRUE(to.is_valid());
        EXPECT_TRUE(to.is_terminal());

        auto another = to.find("another");
        EXPECT_TRUE(another.is_valid());
        EXPECT_FALSE(another.is_terminal());

        auto object = to.find("object");
        EXPECT_FALSE(object.is_valid());
        EXPECT_TRUE(object.is_terminal());

    }

}
