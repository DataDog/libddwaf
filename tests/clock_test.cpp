// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestTimer, Basic)
{
    ddwaf::timer deadline{std::chrono::milliseconds(2), 1};
    EXPECT_FALSE(deadline.expired());

    usleep(500);
    EXPECT_FALSE(deadline.expired());

    usleep(1000);
    EXPECT_FALSE(deadline.expired());

    usleep(1000);
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, ExpiredFromConstruction)
{
    ddwaf::timer deadline{std::chrono::milliseconds(0)};
    EXPECT_TRUE(deadline.expired());
}

TEST(TestTimer, ValidatePeriod)
{
    ddwaf::timer deadline{std::chrono::milliseconds(1), 5};
    EXPECT_FALSE(deadline.expired());

    usleep(1000);
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_FALSE(deadline.expired());
    EXPECT_TRUE(deadline.expired());
}
