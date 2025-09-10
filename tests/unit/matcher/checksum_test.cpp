// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "matcher/checksum.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::matcher;

namespace {

TEST(TestChecksum, Luhn)
{
    // Random mastercard
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "5425233430109903"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "54252334 30109903"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "5425 2334 3010 9903"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "54252334-30109903"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "5425-2334-3010-9903"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "54252334_30109903"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "5425_2334_3010_9903"));

    // Random visa
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "4000000000001000"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "40000000 00001000"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "4000 0000 0000 1000"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "40000000-00001000"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "4000-0000-0000-1000"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "40000000_00001000"));
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "4000_0000_0000_1000"));

    // Random IMEI
    EXPECT_TRUE(checksum_eval(checksum_algorithm::luhn, "350009218041876"));

    // Invalid
    EXPECT_FALSE(checksum_eval(checksum_algorithm::luhn, "5427625793410839"));
    EXPECT_FALSE(checksum_eval(checksum_algorithm::luhn, "1"));
    EXPECT_FALSE(checksum_eval(checksum_algorithm::luhn, "1213981928372"));
    EXPECT_FALSE(checksum_eval(checksum_algorithm::luhn, "              "));
    EXPECT_FALSE(checksum_eval(checksum_algorithm::luhn, ""));
}

} // namespace
