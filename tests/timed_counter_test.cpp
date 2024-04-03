// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.hpp"
#include "test_utils.hpp"
#include "timed_counter.hpp"

using namespace std::chrono_literals;

namespace {

TEST(TestTimedCounter, BasicMs)
{
    ddwaf::timed_counter window{10ms, 5};

    EXPECT_EQ(window.add_timepoint_and_count(1ms), 1);
    EXPECT_EQ(window.add_timepoint_and_count(11ms), 1);
    EXPECT_EQ(window.add_timepoint_and_count(12ms), 2);
    EXPECT_EQ(window.add_timepoint_and_count(13ms), 3);
    EXPECT_EQ(window.add_timepoint_and_count(14ms), 4);
    EXPECT_EQ(window.add_timepoint_and_count(15ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(16ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(17ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(18ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(19ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(20ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(21ms), 5);
    EXPECT_EQ(window.add_timepoint_and_count(40ms), 1);
}

TEST(TestTimedCounter, BasicS)
{
    ddwaf::timed_counter window{10s, 5};

    EXPECT_EQ(window.add_timepoint_and_count(1s), 1);
    EXPECT_EQ(window.add_timepoint_and_count(11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count(12s), 2);
    EXPECT_EQ(window.add_timepoint_and_count(13s), 3);
    EXPECT_EQ(window.add_timepoint_and_count(14s), 4);
    EXPECT_EQ(window.add_timepoint_and_count(15s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(16s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(17s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(18s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(19s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count(40s), 1);
}

TEST(TestIndexedTimedCounter, BasicString)
{
    ddwaf::indexed_timed_counter<std::string, std::chrono::milliseconds> window{10s, 5, 5};

    EXPECT_EQ(window.add_timepoint_and_count("admin", 1s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("user", 10s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("docker", 11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("nobody", 11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("root", 11s), 1);
    // Admin should be removed, as it's the latest
    EXPECT_EQ(window.add_timepoint_and_count("mail", 11s), 1);

    // User will now be removed
    EXPECT_EQ(window.add_timepoint_and_count("admin", 11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 12s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 13s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 14s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 15s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 16s), 5);

    EXPECT_EQ(window.add_timepoint_and_count("docker", 17s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("nobody", 17s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("root", 17s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("mail", 17s), 2);

    EXPECT_EQ(window.add_timepoint_and_count("docker", 18s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("nobody", 18s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("root", 18s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("mail", 18s), 3);

    EXPECT_EQ(window.add_timepoint_and_count("docker", 19s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("nobody", 19s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("root", 19s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("mail", 19s), 4);

    EXPECT_EQ(window.add_timepoint_and_count("docker", 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("nobody", 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("root", 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("mail", 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 20s), 5);

    EXPECT_EQ(window.add_timepoint_and_count("nobody", 21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("root", 21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("mail", 21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("admin", 21s), 5);
    // Docker will now be removed
    EXPECT_EQ(window.add_timepoint_and_count("user", 21s), 1);
}

} // namespace
