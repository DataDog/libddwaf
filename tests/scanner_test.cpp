// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "scanner.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
TEST(TestScanner, SimpleMatch)
{
    matcher::base::unique_ptr key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    matcher::base::unique_ptr value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}}, std::move(key_matcher),
        std::move(value_matcher)};

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_TRUE(scnr.eval(key, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, NoMatchOnKey)
{
    matcher::base::unique_ptr key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    matcher::base::unique_ptr value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}}, std::move(key_matcher),
        std::move(value_matcher)};

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "helloo");
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_FALSE(scnr.eval(key, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, NoMatchOnValue)
{
    matcher::base::unique_ptr key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    matcher::base::unique_ptr value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}}, std::move(key_matcher),
        std::move(value_matcher)};

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_string(&value, "192.168.0.2");

    EXPECT_FALSE(scnr.eval(key, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}


} // namespace
