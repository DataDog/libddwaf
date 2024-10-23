// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "transformer/base64_encode.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestBase64encode, NameAndID)
{
    EXPECT_STREQ(transformer::base64_encode::name().data(), "base64_encode");
    EXPECT_EQ(transformer::base64_encode::id(), transformer_id::base64_encode);
}

TEST(TestBase64Encode, EmptyString) { EXPECT_NO_TRANSFORM(base64_encode, ""); }

TEST(TestBase64Encode, ValidTransform)
{
    EXPECT_TRANSFORM(base64_encode, "foobar", "Zm9vYmFy");
    EXPECT_TRANSFORM(base64_encode, "fooba", "Zm9vYmE=");
    EXPECT_TRANSFORM(base64_encode, "foob", "Zm9vYg==");
    EXPECT_TRANSFORM(base64_encode, "foo", "Zm9v");
    EXPECT_TRANSFORM(base64_encode, "fo", "Zm8=");
    EXPECT_TRANSFORM(base64_encode, "f", "Zg==");
    EXPECT_TRANSFORM(base64_encode, "d", "ZA==");
    EXPECT_TRANSFORM(base64_encode, "fooba@", "Zm9vYmFA");
    // Regression, negative characters resulted in a buffer overflow
    EXPECT_TRANSFORM(base64_encode, "\x80\x80\x80\x80\x80\x80", "gICAgICA");
}

TEST(TestBase64Encode, InvalidTransform)
{
    // This transformer has no invalid cases
}

} // namespace
