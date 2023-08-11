// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.hpp"

#include "exclusion/object_filter.hpp"

namespace {

using state = ddwaf::exclusion::path_trie::traverser::state;

TEST(TestPathTrie, Basic)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "to", "object"});
    trie.insert<std::string_view>({"path", "to", "another", "object"});

    auto it = trie.get_traverser();
    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend("to");
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::found);
    }

    {
        auto an_obj = it.descend("path").descend("to").descend("another").descend("object");
        EXPECT_EQ(an_obj.get_state(), state::found);
    }

    trie.insert<std::string>({"path", "to"});
    {
        auto path = trie.get_traverser().descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend("to");
        EXPECT_EQ(to.get_state(), state::found);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::found);

        auto object2 = to.descend("object2");
        EXPECT_EQ(object2.get_state(), state::found);
    }
}

TEST(TestPathTrie, Glob)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "*", "object"});

    auto it = trie.get_traverser();
    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend("to");
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::found);
    }

    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend_wildcard();
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::found);
    }

    {
        auto path = it.descend_wildcard();
        EXPECT_EQ(path.get_state(), state::not_found);
    }
}

TEST(TestPathTrie, MultipleGlobsAndPaths)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "*", "object", "*", "box"});
    trie.insert<std::string>({"path", "was", "closed"});
    trie.insert<std::string>({"path", "*", "object", "but", "empty"});

    auto it = trie.get_traverser();
    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend("to");
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::intermediate_node);

        auto in = object.descend("in");
        EXPECT_EQ(in.get_state(), state::intermediate_node);

        auto box = in.descend("box");
        EXPECT_EQ(box.get_state(), state::found);
    }

    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto was = path.descend("was");
        EXPECT_EQ(was.get_state(), state::intermediate_node);

        {
            auto object = was.descend("object");
            EXPECT_EQ(object.get_state(), state::intermediate_node);

            auto in = object.descend("in");
            EXPECT_EQ(in.get_state(), state::intermediate_node);

            auto box = in.descend("box");
            EXPECT_EQ(box.get_state(), state::found);
        }

        {
            auto closed = was.descend("closed");
            EXPECT_EQ(closed.get_state(), state::found);
        }
    }

    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto was = path.descend("was");
        EXPECT_EQ(was.get_state(), state::intermediate_node);

        auto object = was.descend("object");
        EXPECT_EQ(object.get_state(), state::intermediate_node);

        auto but = object.descend("but");
        EXPECT_EQ(but.get_state(), state::intermediate_node);

        {
            auto box = but.descend("box");
            EXPECT_EQ(box.get_state(), state::found);
        }

        {
            auto empty = but.descend("empty");
            EXPECT_EQ(empty.get_state(), state::found);
        }
    }

    {
        auto path = it.descend("path");
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend_wildcard();
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend("object");
        EXPECT_EQ(object.get_state(), state::intermediate_node);

        auto in = object.descend_wildcard();
        EXPECT_EQ(in.get_state(), state::intermediate_node);

        auto box = in.descend("box");
        EXPECT_EQ(box.get_state(), state::found);
    }
}
TEST(TestPathTrie, Empty)
{
    ddwaf::exclusion::path_trie trie;

    auto it = trie.get_traverser();
    EXPECT_EQ(it.get_state(), state::not_found);

    auto path = it.descend("path");
    EXPECT_EQ(path.get_state(), state::not_found);
}

TEST(TestPathTrie, SetIsFullDomain)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string_view>({});

    auto it = trie.get_traverser();
    EXPECT_EQ(it.get_state(), state::found);

    auto path = it.descend("path");
    EXPECT_EQ(path.get_state(), state::found);
}
} // namespace
