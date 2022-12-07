// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"
#include <gtest/gtest.h>

using state = ddwaf::exclusion::path_trie::traverser::state;

TEST(TestPathTrie, Basic)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "to", "object"});
    trie.insert<std::string_view>({"path", "to", "another", "object"});

    auto it = trie.get_traverser();
    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::GLUE);

        auto to = path.descend("to");
        EXPECT_EQ(path.get_state(), state::GLUE);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::FOUND);
    }

    {
        auto an_obj = it.descend("path").descend("to").descend("another").descend("object");
        EXPECT_EQ(an_obj.get_state(), state::FOUND);
    }

    trie.insert<std::string>({"path", "to"});
    {
        auto path = trie.get_traverser().descend("path");
        EXPECT_EQ(path.get_state(), state::GLUE);

        auto to = path.descend("to");
        EXPECT_EQ(to.get_state(), state::FOUND);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::FOUND);

        auto object2 = to.descend("object2");
        EXPECT_EQ(object2.get_state(), state::FOUND);
    }
}

TEST(TestPathTrie, Empty)
{
    ddwaf::exclusion::path_trie trie;

    auto it = trie.get_traverser();
    EXPECT_EQ(it.get_state(), state::NOT_FOUND);

    auto path = it.descend("path");
    EXPECT_EQ(path.get_state(), state::NOT_FOUND);
}

TEST(TestPathTrie, SetIsFullDomain)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string_view>({});

    auto it = trie.get_traverser();
    EXPECT_EQ(it.get_state(), state::FOUND);

    auto path = it.descend("path");
    EXPECT_EQ(path.get_state(), state::FOUND);
}
