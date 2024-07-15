// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../../test_utils.hpp"

using namespace ddwaf;

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
    EXPECT_EQ(size, 6);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
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

    ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    EXPECT_FALSE(out.timeout);

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 3);

    auto derivatives = test::object_to_map(out.derivatives);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");

    ddwaf_result_free(&out);
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
    EXPECT_EQ(size, 9);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.endpoint"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.header"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.network"));

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

    ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out,
        {.id = "rule1",
            .name = "rule1",
            .tags = {{"type", "flow1"}, {"category", "category1"}},
            .matches = {{.op = "match_regex",
                .op_value = ".*",
                .highlight = "http-put-729d56c3-2c70e12b-2c70e12b",
                .args = {{
                    .value = "http-put-729d56c3-2c70e12b-2c70e12b",
                    .address = "_dd.appsec.fp.http.endpoint",
                    .path = {},
                }}}}},
        {.id = "rule2",
            .name = "rule2",
            .tags = {{"type", "flow2"}, {"category", "category2"}},
            .matches = {{.op = "match_regex",
                .op_value = ".*",
                .highlight = "hdr-1111111111-a441b15f-0-",
                .args = {{
                    .value = "hdr-1111111111-a441b15f-0-",
                    .address = "_dd.appsec.fp.http.header",
                    .path = {},
                }}}}},
        {.id = "rule3",
            .name = "rule3",
            .tags = {{"type", "flow3"}, {"category", "category3"}},
            .matches = {{.op = "match_regex",
                .op_value = ".*",
                .highlight = "net-1-1111111111",
                .args = {{
                    .value = "net-1-1111111111",
                    .address = "_dd.appsec.fp.http.network",
                    .path = {},
                }}}}}

    );

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

    ddwaf_result_free(&out);
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
    EXPECT_EQ(size, 9);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.uri.raw"));
    EXPECT_TRUE(address_set.contains("server.request.method"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.endpoint"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.header"));
    EXPECT_TRUE(address_set.contains("_dd.appsec.fp.http.network"));

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

    ddwaf_object_map_add(&settings, "fingerprint", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out,
        {.id = "rule1",
            .name = "rule1",
            .tags = {{"type", "flow1"}, {"category", "category1"}},
            .matches = {{.op = "match_regex",
                .op_value = ".*",
                .highlight = "http-put-729d56c3-2c70e12b-2c70e12b",
                .args = {{
                    .value = "http-put-729d56c3-2c70e12b-2c70e12b",
                    .address = "_dd.appsec.fp.http.endpoint",
                    .path = {},
                }}}}},
        {.id = "rule2",
            .name = "rule2",
            .tags = {{"type", "flow2"}, {"category", "category2"}},
            .matches = {{.op = "match_regex",
                .op_value = ".*",
                .highlight = "hdr-1111111111-a441b15f-0-",
                .args = {{
                    .value = "hdr-1111111111-a441b15f-0-",
                    .address = "_dd.appsec.fp.http.header",
                    .path = {},
                }}}}},
        {.id = "rule3",
            .name = "rule3",
            .tags = {{"type", "flow3"}, {"category", "category3"}},
            .matches = {{.op = "match_regex",
                .op_value = ".*",
                .highlight = "net-1-1111111111",
                .args = {{
                    .value = "net-1-1111111111",
                    .address = "_dd.appsec.fp.http.network",
                    .path = {},
                }}}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 3);

    auto derivatives = test::object_to_map(out.derivatives);
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.endpoint"], "http-put-729d56c3-2c70e12b-2c70e12b");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.header"], "hdr-1111111111-a441b15f-0-");
    EXPECT_STRV(derivatives["_dd.appsec.fp.http.network"], "net-1-1111111111");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
