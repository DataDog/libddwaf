// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/processors/fingerprint";

TEST(TestFingerprintIntegration, Postprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 9);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.cookies"));
    EXPECT_TRUE(address_set.contains("usr.id"));
    EXPECT_TRUE(address_set.contains("usr.session_id"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 9, alloc);

    auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(body, 1, alloc);
    ddwaf_object_insert_key(body, STRL("key"), alloc);

    auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
    ddwaf_object_set_map(query, 1, alloc);
    ddwaf_object_insert_key(query, STRL("key"), alloc);

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
        STRL("/path/to/resource/?key="));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

    auto *headers = ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 20, alloc);
    ddwaf_object_insert_key(headers, STRL("referer"), alloc);
    ddwaf_object_insert_key(headers, STRL("connection"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-encoding"), alloc);
    ddwaf_object_insert_key(headers, STRL("content-encoding"), alloc);
    ddwaf_object_insert_key(headers, STRL("cache-control"), alloc);
    ddwaf_object_insert_key(headers, STRL("te"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-charset"), alloc);
    ddwaf_object_insert_key(headers, STRL("content-type"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-language"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Random"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(headers, STRL("x-forwarded-for"), alloc), STRL("::1"));
    ddwaf_object_insert_key(headers, STRL("x-real-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("true-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-forwarded"), alloc);
    ddwaf_object_insert_key(headers, STRL("forwarded-for"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-cluster-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("fastly-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("cf-connecting-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("cf-connecting-ipv6"), alloc);

    auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
    ddwaf_object_set_map(cookies, 7, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("name"), alloc), STRL("albert"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("theme"), alloc), STRL("dark"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("language"), alloc), STRL("en-GB"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("tracking_id"), alloc), STRL("xyzabc"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("gdpr_consent"), alloc), STRL("yes"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("session_id"), alloc), STRL("ansd0182u2n"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("last_visit"), alloc), STRL("2024-07-16T12:00:00Z"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

    auto *processor = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(processor, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(processor, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 4);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");
    EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, PostprocessorRegeneration)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 9);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.cookies"));
    EXPECT_TRUE(address_set.contains("usr.id"));
    EXPECT_TRUE(address_set.contains("usr.session_id"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 4, alloc);

        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
            STRL("/path/to/resource/?key="));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

        auto *headers =
            ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
        ddwaf_object_set_map(headers, 20, alloc);
        ddwaf_object_insert_key(headers, STRL("referer"), alloc);
        ddwaf_object_insert_key(headers, STRL("connection"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-encoding"), alloc);
        ddwaf_object_insert_key(headers, STRL("content-encoding"), alloc);
        ddwaf_object_insert_key(headers, STRL("cache-control"), alloc);
        ddwaf_object_insert_key(headers, STRL("te"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-charset"), alloc);
        ddwaf_object_insert_key(headers, STRL("content-type"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-language"), alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Random"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(headers, STRL("x-forwarded-for"), alloc), STRL("::1"));
        ddwaf_object_insert_key(headers, STRL("x-real-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("true-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-forwarded"), alloc);
        ddwaf_object_insert_key(headers, STRL("forwarded-for"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-cluster-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("fastly-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("cf-connecting-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("cf-connecting-ipv6"), alloc);

        auto *processor = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(processor, 1, alloc);
        ddwaf_object_set_bool(ddwaf_object_insert_key(processor, STRL("fingerprint"), alloc), true);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(body, 1, alloc);
        ddwaf_object_insert_key(body, STRL("key"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--2c70e12b");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
        ddwaf_object_set_map(query, 1, alloc);
        ddwaf_object_insert_key(query, STRL("key"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
        ddwaf_object_set_map(cookies, 7, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("name"), alloc), STRL("albert"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("theme"), alloc), STRL("dark"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("language"), alloc), STRL("en-GB"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("tracking_id"), alloc), STRL("xyzabc"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("gdpr_consent"), alloc), STRL("yes"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("session_id"), alloc), STRL("ansd0182u2n"));
        ddwaf_object_set_string_literal(ddwaf_object_insert_key(cookies, STRL("last_visit"), alloc),
            STRL("2024-07-16T12:00:00Z"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn--df6143bc-60ba1602-");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

        ddwaf_object_destroy(&out, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, Preprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 13);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.cookies"));
    EXPECT_TRUE(address_set.contains("usr.id"));
    EXPECT_TRUE(address_set.contains("usr.session_id"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.endpoint"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.header"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.network"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.session"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 9, alloc);

    auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(body, 1, alloc);
    ddwaf_object_insert_key(body, STRL("key"), alloc);

    auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
    ddwaf_object_set_map(query, 1, alloc);
    ddwaf_object_insert_key(query, STRL("key"), alloc);

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
        STRL("/path/to/resource/?key="));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

    auto *headers = ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 20, alloc);
    ddwaf_object_insert_key(headers, STRL("referer"), alloc);
    ddwaf_object_insert_key(headers, STRL("connection"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-encoding"), alloc);
    ddwaf_object_insert_key(headers, STRL("content-encoding"), alloc);
    ddwaf_object_insert_key(headers, STRL("cache-control"), alloc);
    ddwaf_object_insert_key(headers, STRL("te"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-charset"), alloc);
    ddwaf_object_insert_key(headers, STRL("content-type"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-language"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Random"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(headers, STRL("x-forwarded-for"), alloc), STRL("::1"));
    ddwaf_object_insert_key(headers, STRL("x-real-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("true-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-forwarded"), alloc);
    ddwaf_object_insert_key(headers, STRL("forwarded-for"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-cluster-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("fastly-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("cf-connecting-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("cf-connecting-ipv6"), alloc);

    auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
    ddwaf_object_set_map(cookies, 7, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("name"), alloc), STRL("albert"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("theme"), alloc), STRL("dark"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("language"), alloc), STRL("en-GB"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("tracking_id"), alloc), STRL("xyzabc"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("gdpr_consent"), alloc), STRL("yes"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("session_id"), alloc), STRL("ansd0182u2n"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("last_visit"), alloc), STRL("2024-07-16T12:00:00Z"));

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

    auto *processor = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(processor, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(processor, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(out,
        {.id = "rule1",
            .name = "rule1",
            .tags = {{"type", "flow1"}, {"category", "category1"}},
            .matches = {{.op = "match_regex",
                .op_value = "http-put-729d56c3-2c70e12b-2c70e12b",
                .highlight = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                .args = {{
                    .value = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                    .address = "_dd.appsec.fp.http.endpoint",
                    .path = {},
                }}}}},
        {.id = "rule2",
            .name = "rule2",
            .tags = {{"type", "flow2"}, {"category", "category2"}},
            .matches = {{.op = "match_regex",
                .op_value = "hdr-1111111111-a441b15f-0-",
                .highlight = "hdr-1111111111-a441b15f-0-"sv,
                .args = {{
                    .value = "hdr-1111111111-a441b15f-0-"sv,
                    .address = "_dd.appsec.fp.http.header",
                    .path = {},
                }}}}},
        {.id = "rule3",
            .name = "rule3",
            .tags = {{"type", "flow3"}, {"category", "category3"}},
            .matches = {{.op = "match_regex",
                .op_value = "net-1-1111111111",
                .highlight = "net-1-1111111111"sv,
                .args = {{
                    .value = "net-1-1111111111"sv,
                    .address = "_dd.appsec.fp.http.network",
                    .path = {},
                }}}}},
        {.id = "rule4",
            .name = "rule4",
            .tags = {{"type", "flow4"}, {"category", "category4"}},
            .matches = {{.op = "match_regex",
                .op_value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3",
                .highlight = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                .args = {{
                    .value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                    .address = "_dd.appsec.fp.session",
                    .path = {},
                }}}}}, );

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, PreprocessorRegeneration)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 13);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.cookies"));
    EXPECT_TRUE(address_set.contains("usr.id"));
    EXPECT_TRUE(address_set.contains("usr.session_id"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.endpoint"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.header"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.network"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.session"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 4, alloc);

        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
            STRL("/path/to/resource/?key="));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

        auto *headers =
            ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
        ddwaf_object_set_map(headers, 20, alloc);
        ddwaf_object_insert_key(headers, STRL("referer"), alloc);
        ddwaf_object_insert_key(headers, STRL("connection"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-encoding"), alloc);
        ddwaf_object_insert_key(headers, STRL("content-encoding"), alloc);
        ddwaf_object_insert_key(headers, STRL("cache-control"), alloc);
        ddwaf_object_insert_key(headers, STRL("te"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-charset"), alloc);
        ddwaf_object_insert_key(headers, STRL("content-type"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-language"), alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Random"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(headers, STRL("x-forwarded-for"), alloc), STRL("::1"));
        ddwaf_object_insert_key(headers, STRL("x-real-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("true-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-forwarded"), alloc);
        ddwaf_object_insert_key(headers, STRL("forwarded-for"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-cluster-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("fastly-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("cf-connecting-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("cf-connecting-ipv6"), alloc);

        auto *processor = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(processor, 1, alloc);
        ddwaf_object_set_bool(ddwaf_object_insert_key(processor, STRL("fingerprint"), alloc), true);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out,
            {.id = "rule2",
                .name = "rule2",
                .tags = {{"type", "flow2"}, {"category", "category2"}},
                .matches = {{.op = "match_regex",
                    .op_value = "hdr-1111111111-a441b15f-0-",
                    .highlight = "hdr-1111111111-a441b15f-0-"sv,
                    .args = {{
                        .value = "hdr-1111111111-a441b15f-0-"sv,
                        .address = "_dd.appsec.fp.http.header",
                        .path = {},
                    }}}}},
            {.id = "rule3",
                .name = "rule3",
                .tags = {{"type", "flow3"}, {"category", "category3"}},
                .matches = {{.op = "match_regex",
                    .op_value = "net-1-1111111111",
                    .highlight = "net-1-1111111111"sv,
                    .args = {{
                        .value = "net-1-1111111111"sv,
                        .address = "_dd.appsec.fp.http.network",
                        .path = {},
                    }}}}}, );

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);
        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
        ddwaf_object_set_map(query, 1, alloc);
        ddwaf_object_insert_key(query, STRL("key"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(body, 1, alloc);
        ddwaf_object_insert_key(body, STRL("key"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out,
            {.id = "rule1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "http-put-729d56c3-2c70e12b-2c70e12b",
                    .highlight = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                    .args = {{
                        .value = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                        .address = "_dd.appsec.fp.http.endpoint",
                        .path = {},
                    }}}}}, );

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);
        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
        ddwaf_object_set_map(cookies, 7, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("name"), alloc), STRL("albert"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("theme"), alloc), STRL("dark"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("language"), alloc), STRL("en-GB"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("tracking_id"), alloc), STRL("xyzabc"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("gdpr_consent"), alloc), STRL("yes"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("session_id"), alloc), STRL("ansd0182u2n"));
        ddwaf_object_set_string_literal(ddwaf_object_insert_key(cookies, STRL("last_visit"), alloc),
            STRL("2024-07-16T12:00:00Z"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *events = ddwaf_object_find(&out, STRL("events"));
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);
        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out,
            {.id = "rule4",
                .name = "rule4",
                .tags = {{"type", "flow4"}, {"category", "category4"}},
                .matches = {{.op = "match_regex",
                    .op_value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3",
                    .highlight = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                    .args = {{
                        .value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                        .address = "_dd.appsec.fp.session",
                        .path = {},
                    }}}}}, );

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);
        ddwaf_object_destroy(&out, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, Processor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);

    EXPECT_EQ(size, 13);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.cookies"));
    EXPECT_TRUE(address_set.contains("usr.id"));
    EXPECT_TRUE(address_set.contains("usr.session_id"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.endpoint"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.header"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.network"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.session"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 9, alloc);

    auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(body, 1, alloc);
    ddwaf_object_insert_key(body, STRL("key"), alloc);

    auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
    ddwaf_object_set_map(query, 1, alloc);
    ddwaf_object_insert_key(query, STRL("key"), alloc);

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
        STRL("/path/to/resource/?key="));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

    auto *headers = ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 20, alloc);
    ddwaf_object_insert_key(headers, STRL("referer"), alloc);
    ddwaf_object_insert_key(headers, STRL("connection"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-encoding"), alloc);
    ddwaf_object_insert_key(headers, STRL("content-encoding"), alloc);
    ddwaf_object_insert_key(headers, STRL("cache-control"), alloc);
    ddwaf_object_insert_key(headers, STRL("te"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-charset"), alloc);
    ddwaf_object_insert_key(headers, STRL("content-type"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept"), alloc);
    ddwaf_object_insert_key(headers, STRL("accept-language"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Random"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(headers, STRL("x-forwarded-for"), alloc), STRL("::1"));
    ddwaf_object_insert_key(headers, STRL("x-real-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("true-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-forwarded"), alloc);
    ddwaf_object_insert_key(headers, STRL("forwarded-for"), alloc);
    ddwaf_object_insert_key(headers, STRL("x-cluster-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("fastly-client-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("cf-connecting-ip"), alloc);
    ddwaf_object_insert_key(headers, STRL("cf-connecting-ipv6"), alloc);

    auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
    ddwaf_object_set_map(cookies, 7, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("name"), alloc), STRL("albert"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("theme"), alloc), STRL("dark"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("language"), alloc), STRL("en-GB"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("tracking_id"), alloc), STRL("xyzabc"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("gdpr_consent"), alloc), STRL("yes"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("session_id"), alloc), STRL("ansd0182u2n"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(cookies, STRL("last_visit"), alloc), STRL("2024-07-16T12:00:00Z"));

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

    auto *processor = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(processor, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(processor, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(out,
        {.id = "rule1",
            .name = "rule1",
            .tags = {{"type", "flow1"}, {"category", "category1"}},
            .matches = {{.op = "match_regex",
                .op_value = "http-put-729d56c3-2c70e12b-2c70e12b",
                .highlight = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                .args = {{
                    .value = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                    .address = "_dd.appsec.fp.http.endpoint",
                    .path = {},
                }}}}},
        {.id = "rule2",
            .name = "rule2",
            .tags = {{"type", "flow2"}, {"category", "category2"}},
            .matches = {{.op = "match_regex",
                .op_value = "hdr-1111111111-a441b15f-0-",
                .highlight = "hdr-1111111111-a441b15f-0-"sv,
                .args = {{
                    .value = "hdr-1111111111-a441b15f-0-"sv,
                    .address = "_dd.appsec.fp.http.header",
                    .path = {},
                }}}}},
        {.id = "rule3",
            .name = "rule3",
            .tags = {{"type", "flow3"}, {"category", "category3"}},
            .matches = {{.op = "match_regex",
                .op_value = "net-1-1111111111",
                .highlight = "net-1-1111111111"sv,
                .args = {{
                    .value = "net-1-1111111111"sv,
                    .address = "_dd.appsec.fp.http.network",
                    .path = {},
                }}}}},
        {.id = "rule4",
            .name = "rule4",
            .tags = {{"type", "flow4"}, {"category", "category4"}},
            .matches = {{.op = "match_regex",
                .op_value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3",
                .highlight = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                .args = {{
                    .value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                    .address = "_dd.appsec.fp.session",
                    .path = {},
                }}}}}, );

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 4);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");
    EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, ProcessorRegeneration)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);

    EXPECT_EQ(size, 13);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.cookies"));
    EXPECT_TRUE(address_set.contains("usr.id"));
    EXPECT_TRUE(address_set.contains("usr.session_id"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.endpoint"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.header"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.network"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.session"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 4, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
            STRL("/path/to/resource/?key="));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

        auto *headers =
            ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
        ddwaf_object_set_map(headers, 20, alloc);
        ddwaf_object_insert_key(headers, STRL("referer"), alloc);
        ddwaf_object_insert_key(headers, STRL("connection"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-encoding"), alloc);
        ddwaf_object_insert_key(headers, STRL("content-encoding"), alloc);
        ddwaf_object_insert_key(headers, STRL("cache-control"), alloc);
        ddwaf_object_insert_key(headers, STRL("te"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-charset"), alloc);
        ddwaf_object_insert_key(headers, STRL("content-type"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept"), alloc);
        ddwaf_object_insert_key(headers, STRL("accept-language"), alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Random"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(headers, STRL("x-forwarded-for"), alloc), STRL("::1"));
        ddwaf_object_insert_key(headers, STRL("x-real-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("true-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-forwarded"), alloc);
        ddwaf_object_insert_key(headers, STRL("forwarded-for"), alloc);
        ddwaf_object_insert_key(headers, STRL("x-cluster-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("fastly-client-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("cf-connecting-ip"), alloc);
        ddwaf_object_insert_key(headers, STRL("cf-connecting-ipv6"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("fingerprint"), alloc), true);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out,
            {.id = "rule2",
                .name = "rule2",
                .tags = {{"type", "flow2"}, {"category", "category2"}},
                .matches = {{.op = "match_regex",
                    .op_value = "hdr-1111111111-a441b15f-0-",
                    .highlight = "hdr-1111111111-a441b15f-0-"sv,
                    .args = {{
                        .value = "hdr-1111111111-a441b15f-0-"sv,
                        .address = "_dd.appsec.fp.http.header",
                        .path = {},
                    }}}}},
            {.id = "rule3",
                .name = "rule3",
                .tags = {{"type", "flow3"}, {"category", "category3"}},
                .matches = {{.op = "match_regex",
                    .op_value = "net-1-1111111111",
                    .highlight = "net-1-1111111111"sv,
                    .args = {{
                        .value = "net-1-1111111111"sv,
                        .address = "_dd.appsec.fp.http.network",
                        .path = {},
                    }}}}}, );

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
        ddwaf_object_set_map(query, 1, alloc);
        ddwaf_object_insert_key(query, STRL("key"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(body, 1, alloc);
        ddwaf_object_insert_key(body, STRL("key"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out,
            {.id = "rule1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "http-put-729d56c3-2c70e12b-2c70e12b",
                    .highlight = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                    .args = {{
                        .value = "http-put-729d56c3-2c70e12b-2c70e12b"sv,
                        .address = "_dd.appsec.fp.http.endpoint",
                        .path = {},
                    }}}}}, );

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
        ddwaf_object_set_map(cookies, 7, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("name"), alloc), STRL("albert"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("theme"), alloc), STRL("dark"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("language"), alloc), STRL("en-GB"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("tracking_id"), alloc), STRL("xyzabc"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("gdpr_consent"), alloc), STRL("yes"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(cookies, STRL("session_id"), alloc), STRL("ansd0182u2n"));
        ddwaf_object_set_string_literal(ddwaf_object_insert_key(cookies, STRL("last_visit"), alloc),
            STRL("2024-07-16T12:00:00Z"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *events = ddwaf_object_find(&out, STRL("events"));
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn--df6143bc-60ba1602-");

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out,
            {.id = "rule4",
                .name = "rule4",
                .tags = {{"type", "flow4"}, {"category", "category4"}},
                .matches = {{.op = "match_regex",
                    .op_value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3",
                    .highlight = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                    .args = {{
                        .value = "ssn-8c6976e5-df6143bc-60ba1602-269500d3"sv,
                        .address = "_dd.appsec.fp.session",
                        .path = {},
                    }}}}}, );

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

        ddwaf_object_destroy(&out, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, InvalidBodyType)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 5, alloc);

    auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_array(body, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert(body, alloc), STRL("key"));

    auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
    ddwaf_object_set_map(query, 1, alloc);
    ddwaf_object_insert_key(query, STRL("key"), alloc);

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
        STRL("/path/to/resource/?key="));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, InvalidQueryType)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 5, alloc);

    auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(body, 1, alloc);
    ddwaf_object_insert_key(body, STRL("key"), alloc);

    auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
    ddwaf_object_set_array(query, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert(query, alloc), STRL("key"));

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
        STRL("/path/to/resource/?key="));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--2c70e12b");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, InvalidQueryAndBodyType)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 5, alloc);

    auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_array(body, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert(body, alloc), STRL("key"));

    auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
    ddwaf_object_set_array(query, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert(query, alloc), STRL("key"));

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
        STRL("/path/to/resource/?key="));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc), STRL("PuT"));

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, InvalidHeader)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 2, alloc);

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("fingerprint"), alloc), true);

    auto *headers = ddwaf_object_insert_key(&map, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_array(headers, 21, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("referer"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("connection"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("accept-encoding"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("content-encoding"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("cache-control"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("te"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("accept-charset"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("content-type"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("accept"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("accept-language"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("user-agent"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("x-forwarded-for"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("x-real-ip"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("true-client-ip"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("x-client-ip"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("x-forwarded"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("forwarded-for"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert(headers, alloc), STRL("x-cluster-client-ip"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("fastly-client-ip"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(headers, alloc), STRL("cf-connecting-ip"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert(headers, alloc), STRL("cf-connecting-ipv6"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, InvalidCookies)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 4, alloc);

    auto *cookies = ddwaf_object_insert_key(&map, STRL("server.request.cookies"), alloc);
    ddwaf_object_set_array(cookies, 7, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("name"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("theme"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("language"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("tracking_id"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("gdpr_consent"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("session_id"));
    ddwaf_object_set_string_literal(ddwaf_object_insert(cookies, alloc), STRL("last_visit"));

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.id"), alloc), STRL("admin"));
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("usr.session_id"), alloc), STRL("ansd0182u2n"));

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("fingerprint"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5---269500d3");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
