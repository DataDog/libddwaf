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
    std::unique_ptr<matcher::base> key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    std::unique_ptr<matcher::base> value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "PII"}, {"category", "IP"}};
    scanner scnr{"something", tags, std::move(key_matcher), std::move(value_matcher)};
    EXPECT_STREQ(scnr.get_id().data(), "something");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_TRUE(scnr.eval(key, value));

    std::string_view key_sv{key.stringValue, static_cast<std::size_t>(key.nbEntries)};
    EXPECT_TRUE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, SimpleMatchNoKeyMatcher)
{
    std::unique_ptr<matcher::base> value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "PII"}, {"category", "IP"}};
    scanner scnr{"something", tags, {}, std::move(value_matcher)};
    EXPECT_STREQ(scnr.get_id().data(), "something");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_TRUE(scnr.eval(key, value));

    std::string_view key_sv{key.stringValue, static_cast<std::size_t>(key.nbEntries)};
    EXPECT_TRUE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, SimpleMatchNoValueMatcher)
{
    std::unique_ptr<matcher::base> key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    std::unordered_map<std::string, std::string> tags{{"type", "PII"}, {"category", "IP"}};
    scanner scnr{"something", tags, std::move(key_matcher), {}};
    EXPECT_STREQ(scnr.get_id().data(), "something");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_TRUE(scnr.eval(key, value));

    std::string_view key_sv{key.stringValue, static_cast<std::size_t>(key.nbEntries)};
    EXPECT_TRUE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, NoMatchOnKey)
{
    std::unique_ptr<matcher::base> key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    std::unique_ptr<matcher::base> value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{
        {"type", "PII"}, {"category", "IP"}, {"danger", "0"}};
    scanner scnr{"0", tags, std::move(key_matcher), std::move(value_matcher)};
    EXPECT_STREQ(scnr.get_id().data(), "0");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "helloo");
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_FALSE(scnr.eval(key, value));

    std::string_view key_sv{key.stringValue, static_cast<std::size_t>(key.nbEntries)};
    EXPECT_FALSE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, NoMatchOnValue)
{
    std::unique_ptr<matcher::base> key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    std::unique_ptr<matcher::base> value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{};
    scanner scnr{"null", tags, std::move(key_matcher), std::move(value_matcher)};
    EXPECT_STREQ(scnr.get_id().data(), "null");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_string(&value, "192.168.0.2");

    EXPECT_FALSE(scnr.eval(key, value));

    std::string_view key_sv{key.stringValue, static_cast<std::size_t>(key.nbEntries)};
    EXPECT_FALSE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, InvalidKey)
{
    std::unique_ptr<matcher::base> key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    std::unique_ptr<matcher::base> value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{
        {"type", "PII"}, {"category", "IP"}, {"danger", "0"}};
    scanner scnr{"0", tags, std::move(key_matcher), std::move(value_matcher)};
    EXPECT_STREQ(scnr.get_id().data(), "0");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_invalid(&key);
    ddwaf_object_string(&value, "192.168.0.1");

    EXPECT_FALSE(scnr.eval(key, value));

    std::string_view key_sv{};
    EXPECT_FALSE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

TEST(TestScanner, InvalidValue)
{
    std::unique_ptr<matcher::base> key_matcher =
        std::make_unique<matcher::exact_match>(std::vector<std::string>{"hello", "goodbye"});

    std::unique_ptr<matcher::base> value_matcher =
        std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{};
    scanner scnr{"null", tags, std::move(key_matcher), std::move(value_matcher)};
    EXPECT_STREQ(scnr.get_id().data(), "null");
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object key;
    ddwaf_object value;

    ddwaf_object_string(&key, "hello");
    ddwaf_object_invalid(&value);

    EXPECT_FALSE(scnr.eval(key, value));

    std::string_view key_sv{key.stringValue, static_cast<std::size_t>(key.nbEntries)};
    EXPECT_FALSE(scnr.eval(key_sv, value));

    ddwaf_object_free(&key);
    ddwaf_object_free(&value);
}

} // namespace
