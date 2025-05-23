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
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object body = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&map, "server.request.body", &body);

    ddwaf_object query = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&map, "server.request.query", &query);

    ddwaf_object_map_add(
        &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
    ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "connection", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "te", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "user-agent", ddwaf_object_string(&tmp, "Random"));
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "::1"));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);
    ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
    ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
    ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
    ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
    ddwaf_object_map_add(&cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

    ddwaf_object_map_add(&map, "server.request.cookies", &cookies);
    ddwaf_object_map_add(&map, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&map, "usr.session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));

    ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 4);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");
    EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, PostprocessorRegeneration)
{
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_map_add(
            &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
        ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

        ddwaf_object headers;
        ddwaf_object_map(&headers);
        ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "connection", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "content-encoding", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "te", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "user-agent", ddwaf_object_string(&tmp, "Random"));
        ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "::1"));
        ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

        ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

        ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 3);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object body = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.body", &body);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--2c70e12b");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object query = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.query", &query);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object cookies;
        ddwaf_object_map(&cookies);
        ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
        ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
        ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
        ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
        ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
        ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
        ddwaf_object_map_add(
            &cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));
        ddwaf_object_map_add(&map, "server.request.cookies", &cookies);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn--df6143bc-60ba1602-");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map_add(&map, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "usr.session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

        ddwaf_object_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, Preprocessor)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object body = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&map, "server.request.body", &body);

    ddwaf_object query = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&map, "server.request.query", &query);

    ddwaf_object_map_add(
        &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
    ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "connection", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "te", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "user-agent", ddwaf_object_string(&tmp, "Random"));
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "::1"));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);
    ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
    ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
    ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
    ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
    ddwaf_object_map_add(&cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

    ddwaf_object_map_add(&map, "server.request.cookies", &cookies);
    ddwaf_object_map_add(&map, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&map, "usr.session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));

    ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
    EXPECT_EQ(ddwaf_object_size(attributes), 0);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, PreprocessorRegeneration)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_map_add(
            &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
        ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

        ddwaf_object headers;
        ddwaf_object_map(&headers);
        ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "connection", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "content-encoding", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "te", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "user-agent", ddwaf_object_string(&tmp, "Random"));
        ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "::1"));
        ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

        ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

        ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        EXPECT_EQ(ddwaf_object_size(attributes), 0);
        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object query = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.query", &query);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object body = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.body", &body);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        EXPECT_EQ(ddwaf_object_size(attributes), 0);
        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object cookies;
        ddwaf_object_map(&cookies);
        ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
        ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
        ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
        ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
        ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
        ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
        ddwaf_object_map_add(
            &cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

        ddwaf_object_map_add(&map, "server.request.cookies", &cookies);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *events = ddwaf_object_find(&out, STRL("events"));
        EXPECT_EQ(ddwaf_object_size(events), 0);

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);
        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map_add(&map, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&map, "usr.session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        EXPECT_EQ(ddwaf_object_size(attributes), 0);
        ddwaf_object_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object body = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&map, "server.request.body", &body);

    ddwaf_object query = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&map, "server.request.query", &query);

    ddwaf_object_map_add(
        &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
    ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "connection", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "te", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "user-agent", ddwaf_object_string(&tmp, "Random"));
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "::1"));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);
    ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
    ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
    ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
    ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
    ddwaf_object_map_add(&cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

    ddwaf_object_map_add(&map, "server.request.cookies", &cookies);
    ddwaf_object_map_add(&map, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&map, "usr.session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));

    ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
    EXPECT_EQ(ddwaf_object_size(attributes), 4);

    auto derivatives = test::object_to_map(*attributes);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");
    EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestFingerprintIntegration, ProcessorRegeneration)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_map_add(
            &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
        ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

        ddwaf_object headers;
        ddwaf_object_map(&headers);
        ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "connection", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "content-encoding", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "te", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "user-agent", ddwaf_object_string(&tmp, "Random"));
        ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "::1"));
        ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

        ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

        ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        EXPECT_EQ(ddwaf_object_size(attributes), 3);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3--");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object query = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.query", &query);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object body = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.body", &body);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object cookies;
        ddwaf_object_map(&cookies);
        ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
        ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
        ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
        ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
        ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
        ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
        ddwaf_object_map_add(
            &cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

        ddwaf_object_map_add(&map, "server.request.cookies", &cookies);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *events = ddwaf_object_find(&out, STRL("events"));
        EXPECT_EQ(ddwaf_object_size(events), 0);

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(derivatives["_dd.appsec.fp.session"], "ssn--df6143bc-60ba1602-");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object tmp;

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&map, "usr.session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto derivatives = test::object_to_map(*attributes);
        EXPECT_STRV(
            derivatives["_dd.appsec.fp.session"], "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

        ddwaf_object_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
