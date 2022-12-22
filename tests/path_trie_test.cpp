// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "exclusion/object_filter.hpp"
#include "test.h"
#include <gtest/gtest.h>

using state = ddwaf::exclusion::path_trie::traverser::state;
using path = ddwaf::exclusion::path_trie::path;

struct mpath {
    path *p{};
    const path *stop_p{};
    ~mpath() {
        path *prev = p;
        while (prev != stop_p) {
            path *cur = prev;
            prev = cur->prev;
            delete cur;
        }
    }
    mpath() = default;
    mpath(const mpath&) = delete;
    mpath(mpath&&) = delete;
    mpath& operator=(const mpath&) = delete;
    mpath& operator=(mpath&&) = delete;

    operator const path*() { // NOLINT
        return p;
    }

    mpath& operator[](std::string_view sv) {
        p = new path(p, sv);
        return *this;
    }
    [[nodiscard]] mpath derive() const {
        return mpath{p};
    };

private:
    explicit mpath(path *p) : p{p}, stop_p{p} {}
};

TEST(TestPathTrie, Basic)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "to", "object"});
    trie.insert<std::string_view>({"path", "to", "another", "object"});

    auto it = trie.get_traverser();
    {
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend(mp["to"]);
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::found);
    }

    {
        mpath mp;
        auto an_obj =
            it.descend(mp["path"]).descend(mp["to"]).descend(mp["another"]).descend(mp["object"]);
        EXPECT_EQ(an_obj.get_state(), state::found);
    }

    trie.insert<std::string>({"path", "to"});
    {
        mpath mp;
        auto path = trie.get_traverser().descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend(mp["to"]);
        EXPECT_EQ(to.get_state(), state::found);

        mpath mp_to = mp.derive();
        auto object = to.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::found);

        auto object2 = to.descend(mp_to["object2"]);
        EXPECT_EQ(object2.get_state(), state::found);
    }
}

TEST(TestPathTrie, Glob)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string>({"path", "*", "object"});

    auto it = trie.get_traverser();
    {
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend(mp["to"]);
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::found);
    }

    {
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend(mp[""]);
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::found);
    }

    {
        path empty_path{""};
        auto path = it.descend(&empty_path);
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
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend(mp["to"]);
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::intermediate_node);

        auto in = object.descend(mp["in"]);
        EXPECT_EQ(in.get_state(), state::intermediate_node);

        auto box = in.descend(mp["box"]);
        EXPECT_EQ(box.get_state(), state::found);
    }

    {
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto was = path.descend(mp["was"]);
        EXPECT_EQ(was.get_state(), state::intermediate_node);

        {
            mpath mpi = mp.derive();
            auto object = was.descend(mpi["object"]);
            EXPECT_EQ(object.get_state(), state::intermediate_node);

            auto in = object.descend(mpi["in"]);
            EXPECT_EQ(in.get_state(), state::intermediate_node);

            auto box = in.descend(mpi["box"]);
            EXPECT_EQ(box.get_state(), state::found);
        }

        {
            mpath mpi = mp.derive();
            auto closed = was.descend(mpi["closed"]);
            EXPECT_EQ(closed.get_state(), state::found);
        }
    }

    {
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto was = path.descend(mp["was"]);
        EXPECT_EQ(was.get_state(), state::intermediate_node);

        auto object = was.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::intermediate_node);

        auto but = object.descend(mp["but"]);
        EXPECT_EQ(but.get_state(), state::intermediate_node);

        {
            mpath mp2 = mp.derive();
            auto box = but.descend(mp2["box"]);
            EXPECT_EQ(box.get_state(), state::found);
        }

        {
            mpath mp2 = mp.derive();
            auto empty = but.descend(mp2["empty"]);
            EXPECT_EQ(empty.get_state(), state::found);
        }
    }

    {
        mpath mp;
        auto path = it.descend(mp["path"]);
        EXPECT_EQ(path.get_state(), state::intermediate_node);

        auto to = path.descend(mp[""]);
        EXPECT_EQ(to.get_state(), state::intermediate_node);

        auto object = to.descend(mp["object"]);
        EXPECT_EQ(object.get_state(), state::intermediate_node);

        auto in = object.descend(mp[""]);
        EXPECT_EQ(in.get_state(), state::intermediate_node);

        auto box = in.descend(mp["box"]);
        EXPECT_EQ(box.get_state(), state::found);
    }
}
TEST(TestPathTrie, Empty)
{
    ddwaf::exclusion::path_trie trie;

    auto it = trie.get_traverser();
    EXPECT_EQ(it.get_state(), state::not_found);

    mpath mp;
    auto path = it.descend(mp["path"]);
    EXPECT_EQ(path.get_state(), state::not_found);
}

TEST(TestPathTrie, SetIsFullDomain)
{
    ddwaf::exclusion::path_trie trie;
    trie.insert<std::string_view>({});

    auto it = trie.get_traverser();
    EXPECT_EQ(it.get_state(), state::found);

    mpath mp;
    auto path = it.descend(mp["path"]);
    EXPECT_EQ(path.get_state(), state::found);
}
