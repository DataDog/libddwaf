// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/base64_decode.hpp"
#include "transformer_utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestBase64Decode, NameAndID)
{
    EXPECT_STRV(transformer::base64_decode::name(), "base64_decode");
    EXPECT_EQ(transformer::base64_decode::id(), transformer_id::base64_decode);
}

TEST(TestBase64Decode, EmptyString) { EXPECT_NO_TRANSFORM(base64_decode, ""); }

TEST(TestBase64Decode, ValidTransform)
{
    EXPECT_TRANSFORM(base64_decode, "eyJrZXkiOiJ+fjEifQ==", R"({"key":"~~1"})");
    EXPECT_TRANSFORM(base64_decode, "eyJrZXkiOiJ+fjEifQ=", R"({"key":"~~1"})");
    EXPECT_TRANSFORM(base64_decode, "eyJrZXkiOiJ+fjEifQ", R"({"key":"~~1"})");
    EXPECT_TRANSFORM(
        base64_decode, "eyJ1cmwiOiJsb2dpbnM/X2Q9MTIifQ==", R"({"url":"logins?_d=12"})");
    EXPECT_TRANSFORM(base64_decode, "eyJ1cmwiOiJsb2dpbnM/X2Q9MTIifQ=", R"({"url":"logins?_d=12"})");
    EXPECT_TRANSFORM(base64_decode, "eyJ1cmwiOiJsb2dpbnM/X2Q9MTIifQ", R"({"url":"logins?_d=12"})");
    EXPECT_TRANSFORM(base64_decode, "Zm9vYmFy", "foobar");
    EXPECT_TRANSFORM(base64_decode, "Zm9vYmE=", "fooba");
    EXPECT_TRANSFORM(base64_decode, "Zm9vYg==", "foob");
    EXPECT_TRANSFORM(base64_decode, "Zm9v", "foo");
    EXPECT_TRANSFORM(base64_decode, "Zm8=", "fo");
    EXPECT_TRANSFORM(base64_decode, "Zg==", "f");
    EXPECT_TRANSFORM(base64_decode, "ZA==", "d");
    EXPECT_TRANSFORM(base64_decode, "ZAA=", "d");
    EXPECT_TRANSFORM(base64_decode, "Zm9vYmF", "fooba@");
}

TEST(TestBase64Decode, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(base64_decode, "normal sentence");
    EXPECT_NO_TRANSFORM(base64_decode, "normalsentence===");
    EXPECT_NO_TRANSFORM(base64_decode, "eyJrZXkiOiJ-fjEifQ==");
    EXPECT_NO_TRANSFORM(base64_decode, "eyJrZXkiOiJ-fjEifQ=");
    EXPECT_NO_TRANSFORM(base64_decode, "eyJrZXkiOiJ-fjEifQ");
    EXPECT_NO_TRANSFORM(base64_decode, "eyJ1cmwiOiJsb2dpbnM_X2Q9MTIifQ==");
    EXPECT_NO_TRANSFORM(base64_decode, "eyJ1cmwiOiJsb2dpbnM_X2Q9MTIifQ=");
    EXPECT_NO_TRANSFORM(base64_decode, "eyJ1cmwiOiJsb2dpbnM_X2Q9MTIifQ");
}

} // namespace
