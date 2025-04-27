// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/processors/jwt_decoder";

TEST(TestJwtDecoderIntegration, Preprocessor)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.jwt"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;

    ddwaf_object map = DDWAF_OBJECT_MAP;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer "
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .args = {{
                                   .value = "RS384",
                                   .address = "server.request.jwt",
                                   .path = {"header", "alg"},
                               }}}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestJwtDecoderIntegration, Postprocessor)
{
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 1);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;

    ddwaf_object map = DDWAF_OBJECT_MAP;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer "
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    EXPECT_FALSE(out.timeout);

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    EXPECT_JSON(out.derivatives,
        R"({"server.request.jwt":{"header":{"alg":"RS384","typ":"JWT"},"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022},"signature":true}})");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestJwtDecoderIntegration, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.headers.no_cookies"));
    EXPECT_TRUE(address_set.contains("server.request.jwt"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;

    ddwaf_object map = DDWAF_OBJECT_MAP;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer "
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    ddwaf_object_map_add(&map, "server.request.headers.no_cookies", &headers);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .args = {{
                                   .value = "RS384",
                                   .address = "server.request.jwt",
                                   .path = {"header", "alg"},
                               }}}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    EXPECT_JSON(out.derivatives,
        R"({"server.request.jwt":{"header":{"alg":"RS384","typ":"JWT"},"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022},"signature":true}})");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
