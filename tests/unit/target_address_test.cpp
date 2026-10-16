// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <string>
#include <string_view>
#include <vector>

#include "target_address.hpp"

#include "common/fork_utils.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestTargetAddress, IndexIsStable)
{
    auto first = get_target_index("target_address_test.stable");
    auto second = get_target_index(std::string{"target_address_test.stable"});
    EXPECT_EQ(first, second);
    EXPECT_EQ(target_address{"target_address_test.stable"}.index, first);
}

TEST(TestTargetAddress, IndicesAreDense)
{
    auto lookup = get_target_lookup();
    auto first = get_target_index("target_address_test.dense.first");
    auto second = get_target_index("target_address_test.dense.second");
    EXPECT_NE(first, second);

    // Indices are assigned in sequence, after those of the previous lookup
    EXPECT_GE(first, lookup->size());
    EXPECT_GE(second, lookup->size());
    EXPECT_LT(first, get_target_lookup()->size());
    EXPECT_LT(second, get_target_lookup()->size());
}

TEST(TestTargetAddress, LookupContainsRegisteredAddresses)
{
    auto index = get_target_index("target_address_test.lookup");
    auto lookup = get_target_lookup();
    EXPECT_EQ(lookup->find("target_address_test.lookup"), index);
    EXPECT_EQ(lookup->find("target_address_test.lookup.unregistered"), target_lookup::npos);

    // The lookup is immutable
    auto other = get_target_index("target_address_test.lookup.after");
    EXPECT_EQ(lookup->find("target_address_test.lookup.after"), target_lookup::npos);
    EXPECT_EQ(get_target_lookup()->find("target_address_test.lookup.after"), other);

    // ...and it's reused while no address is registered
    EXPECT_EQ(get_target_lookup(), get_target_lookup());
}

TEST(TestTargetAddress, LookupContainsContextEvent)
{
    EXPECT_EQ(
        get_target_lookup()->find(context_event_address), get_target_index(context_event_address));
}

TEST(TestTargetLookup, Empty)
{
    const target_lookup lookup;
    EXPECT_EQ(lookup.size(), 0);
    EXPECT_EQ(lookup.find(""), target_lookup::npos);
    EXPECT_EQ(lookup.find("server.request.query"), target_lookup::npos);
}

TEST(TestTargetLookup, Find)
{
    std::vector<std::string> storage;
    // Lengths around the word size, prefixes of each other and an empty name
    storage.emplace_back("");
    for (std::size_t i = 1; i <= 40; ++i) { storage.emplace_back(std::string(i, 'a')); }
    for (std::size_t i = 0; i < 200; ++i) {
        storage.emplace_back("server.request." + std::to_string(i));
    }
    storage.emplace_back("server.request.query");
    storage.emplace_back("server.request.headers.no_cookies");

    const std::vector<std::string_view> names{storage.begin(), storage.end()};
    const target_lookup lookup{names};
    EXPECT_EQ(lookup.size(), names.size());

    for (std::size_t i = 0; i < names.size(); ++i) { EXPECT_EQ(lookup.find(names[i]), i); }

    EXPECT_EQ(lookup.find(std::string(41, 'a')), target_lookup::npos);
    EXPECT_EQ(lookup.find("b"), target_lookup::npos);
    EXPECT_EQ(lookup.find("server.request.200"), target_lookup::npos);
    EXPECT_EQ(lookup.find("server.request.quer"), target_lookup::npos);
    EXPECT_EQ(lookup.find("server.request.queryx"), target_lookup::npos);
    EXPECT_EQ(lookup.find("server.request.headers.no_cookie"), target_lookup::npos);
}

TEST(TestTargetLookup, HashDependsOnLengthAndContent)
{
    EXPECT_EQ(
        target_lookup::hash("server.request.query"), target_lookup::hash("server.request.query"));
    EXPECT_NE(target_lookup::hash(""), target_lookup::hash(std::string_view{"\0", 1}));
    EXPECT_NE(target_lookup::hash("abcdefgh"), target_lookup::hash("abcdefgi"));
    EXPECT_NE(target_lookup::hash("abcdefghi"), target_lookup::hash("abcdefghj"));
}

#ifndef _WIN32
// A child forked while another thread holds the lock of the registry (e.g.
// while building a ruleset) can still register addresses.
TEST(TestTargetAddress, ForkWhileRegistryLocked)
{
    EXPECT_TRUE(test::fork_while_locked(lock_target_registry, unlock_target_registry, [] {
        auto index = get_target_index("target_address_test.fork");
        return get_target_lookup()->find("target_address_test.fork") == index;
    }));
}
#endif

} // namespace
