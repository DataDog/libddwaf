// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "clock.hpp"

#include <chrono>
#include <thread>

#include "common/gtest_utils.hpp"

using namespace std::literals;

namespace {

TEST(TestTimer, Basic)
{
    ddwaf::base_timer<1> deadline{2ms};
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(2ms);
    EXPECT_TRUE(deadline.expired());
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, ExpiredFromConstruction)
{
    ddwaf::timer deadline{0us};
    EXPECT_TRUE(deadline.expired());
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, ValidatePeriod)
{
    ddwaf::base_timer<5> deadline{1ms};
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(1ms);
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_TRUE(deadline.expired());
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, EndlessTimer)
{
    // Simple sanity check, we can't really test this
    auto deadline = ddwaf::endless_timer();
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(1ms);
    EXPECT_FALSE(deadline.expired());
}

} // namespace
