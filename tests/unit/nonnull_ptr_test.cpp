// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "pointer.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestNonNullPtr, Nullptr)
{
    int *value = nullptr;
    EXPECT_THROW(nonnull_ptr<int>{value}, std::invalid_argument);
}

TEST(TestNonNullPtr, ValidPtr)
{
    std::vector<int> value{1, 2, 3, 4};

    nonnull_ptr<std::vector<int>> ptr{&value};
    EXPECT_EQ(ptr.get(), &value);
    EXPECT_EQ(ptr->size(), value.size());
    EXPECT_EQ((*ptr).size(), value.size());

    EXPECT_TRUE(ptr == &value);
    EXPECT_FALSE(ptr != &value);

    {
        std::vector<int> other;
        EXPECT_FALSE(ptr == &other);
        EXPECT_TRUE(ptr != &other);
    }

    {
        const std::vector<int> &other{ptr};
        EXPECT_EQ(other.size(), 4);
    }
}

} // namespace
