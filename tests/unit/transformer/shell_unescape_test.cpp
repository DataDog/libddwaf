// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/shell_unescape.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestShellUnescape, NameAndID)
{
    EXPECT_STREQ(transformer::shell_unescape::name().data(), "shell_unescape");
    EXPECT_EQ(transformer::shell_unescape::id(), transformer_id::shell_unescape);
}

TEST(TestShellUnescape, EmptyString) { EXPECT_NO_TRANSFORM(shell_unescape, ""); }

TEST(TestShellUnescape, ValidTransform)
{
    EXPECT_TRANSFORM(shell_unescape, "normal sentence (really)", "normal sentence(really)");
    EXPECT_TRANSFORM(shell_unescape, "normal sentence /really", "normal sentence/really");
    EXPECT_TRANSFORM(shell_unescape, "normal\\ sent\"enc'e re^ally", "normal sentence really");
    EXPECT_TRANSFORM(shell_unescape, "normal;sentence,really", "normal sentence really");
    EXPECT_TRANSFORM(shell_unescape, "normal; sentence, really", "normal sentence really");
    EXPECT_TRANSFORM(
        shell_unescape, "normal sentence \t \v \f \n \r  really", "normal sentence really");
    EXPECT_TRANSFORM(shell_unescape, "normal sentence REALLY", "normal sentence really");

    // More aggressive corner case validation
    EXPECT_TRANSFORM(
        shell_unescape, "normal sentence \t \v \f \n \r  (really)", "normal sentence(really)");
    EXPECT_TRANSFORM(shell_unescape, "bla '", "bla ");
    EXPECT_TRANSFORM(shell_unescape, "bla ;", "bla ");
    EXPECT_TRANSFORM(shell_unescape, "bla /", "bla/");
    EXPECT_TRANSFORM(shell_unescape, "bLaBlAbLa", "blablabla");
    EXPECT_TRANSFORM(shell_unescape, "BlAbLaBlA", "blablabla");
}

TEST(TestShellUnescape, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(shell_unescape, "normal sentence(really)");
}

} // namespace
