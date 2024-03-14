// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <regex>

#include "test.hpp"
#include "uuid.hpp"

namespace {

TEST(TestPseudoUUIDv4, Basic)
{
    unsigned samples = 35;

    std::regex uuid_regex("^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-1b[a-f0-9]{2}-[a-f0-9]{12}$",
        std::regex_constants::icase);
    while (samples-- > 0) {
        auto uuid = ddwaf::uuidv4_generate_pseudo();
        EXPECT_TRUE(std::regex_match(uuid, uuid_regex));
    }
}

} // namespace
