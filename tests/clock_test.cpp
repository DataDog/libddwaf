// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestTimer, Basic)
{
    ddwaf::timer deadline{2ms, 1};
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(500us);
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(1000us);
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(1000us);
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, ExpiredFromConstruction)
{
    ddwaf::timer deadline{0us};
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, ValidatePeriod)
{
    ddwaf::timer deadline{1ms, 5};
    EXPECT_FALSE(deadline.expired());

    std::this_thread::sleep_for(1000us);
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_TRUE(deadline.expired());
}
