// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "sliding_window_counter.hpp"
#include "test.hpp"
#include "test_utils.hpp"

using namespace std::literals;
using namespace std::chrono_literals;

namespace {

TEST(TestTimedCounter, BasicMs)
{
    ddwaf::sliding_window_counter window{10ms, 5};

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
    ddwaf::sliding_window_counter window{10s, 5};

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
    ddwaf::indexed_sliding_window_counter<std::string, std::chrono::milliseconds> window{10s, 5, 5};

    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 1s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("user"sv, 10s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("docker"sv, 11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("nobody"sv, 11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("root"sv, 11s), 1);
    // Admin should be removed, as it's the latest
    EXPECT_EQ(window.add_timepoint_and_count("mail"sv, 11s), 1);

    // User will now be removed
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 11s), 1);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 12s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 13s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 14s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 15s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 16s), 5);

    EXPECT_EQ(window.add_timepoint_and_count("docker"sv, 17s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("nobody"sv, 17s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("root"sv, 17s), 2);
    EXPECT_EQ(window.add_timepoint_and_count("mail"sv, 17s), 2);

    EXPECT_EQ(window.add_timepoint_and_count("docker"sv, 18s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("nobody"sv, 18s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("root"sv, 18s), 3);
    EXPECT_EQ(window.add_timepoint_and_count("mail"sv, 18s), 3);

    EXPECT_EQ(window.add_timepoint_and_count("docker"sv, 19s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("nobody"sv, 19s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("root"sv, 19s), 4);
    EXPECT_EQ(window.add_timepoint_and_count("mail"sv, 19s), 4);

    EXPECT_EQ(window.add_timepoint_and_count("docker"sv, 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("nobody"sv, 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("root"sv, 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("mail"sv, 20s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 20s), 5);

    EXPECT_EQ(window.add_timepoint_and_count("nobody"sv, 21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("root"sv, 21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("mail"sv, 21s), 5);
    EXPECT_EQ(window.add_timepoint_and_count("admin"sv, 21s), 5);
    // Docker will now be removed
    EXPECT_EQ(window.add_timepoint_and_count("user"sv, 21s), 1);
}

} // namespace
