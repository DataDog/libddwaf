// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "../test_utils.hpp"
#include "ddwaf.h"
#include "matcher/regex_match.hpp"
#include "processor/fingerprint.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestHttpEndpointFingerprint, Basic)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_map(&query);
    ddwaf_object_map_add(&query, "Key1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "key,3", ddwaf_object_invalid(&tmp));

    ddwaf_object body;
    ddwaf_object_map(&body);
    ddwaf_object_map_add(&body, "KEY1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "3", ddwaf_object_invalid(&tmp));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, EmptyQuery)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_map(&query);

    ddwaf_object body;
    ddwaf_object_map(&body);
    ddwaf_object_map_add(&body, "KEY1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "3", ddwaf_object_invalid(&tmp));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http-get-0ede9e60--9798c0e4");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, EmptyBody)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_map(&query);
    ddwaf_object_map_add(&query, "Key1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "key,3", ddwaf_object_invalid(&tmp));

    ddwaf_object body;
    ddwaf_object_map(&body);

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, EmptyEverything)
{
    ddwaf_object query;
    ddwaf_object_map(&query);

    ddwaf_object body;
    ddwaf_object_map(&body);

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, ""}, {{}, {}, false, ""},
        {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http----");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, KeyConsistency)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_map(&query);
    ddwaf_object_map_add(&query, "Key1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "key3,Key4", ddwaf_object_invalid(&tmp));

    ddwaf_object body;
    ddwaf_object_map(&body);
    ddwaf_object_map_add(&body, "KeY1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "kEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY3", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KeY4", ddwaf_object_invalid(&tmp));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http-get-0ede9e60-ced401fa-ff07216e");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, InvalidQueryType)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_array(&query);
    ddwaf_object_array_add(&query, ddwaf_object_string(&tmp, "Key1"));
    ddwaf_object_array_add(&query, ddwaf_object_string(&tmp, "KEY2"));
    ddwaf_object_array_add(&query, ddwaf_object_string(&tmp, "key,3"));

    ddwaf_object body;
    ddwaf_object_map(&body);
    ddwaf_object_map_add(&body, "KEY1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "3", ddwaf_object_invalid(&tmp));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http-get-0ede9e60--9798c0e4");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, InvalidBodyType)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_map(&query);
    ddwaf_object_map_add(&query, "Key1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "key,3", ddwaf_object_invalid(&tmp));

    ddwaf_object body;
    ddwaf_object_array(&body);
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "KEY1"));
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "KEY2"));
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "KEY"));
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "3"));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, InvalidQueryAndBodyType)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_array(&query);
    ddwaf_object_array_add(&query, ddwaf_object_string(&tmp, "Key1"));
    ddwaf_object_array_add(&query, ddwaf_object_string(&tmp, "KEY2"));
    ddwaf_object_array_add(&query, ddwaf_object_string(&tmp, "key,3"));

    ddwaf_object body;
    ddwaf_object_array(&body);
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "KEY1"));
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "KEY2"));
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "KEY"));
    ddwaf_object_array_add(&body, ddwaf_object_string(&tmp, "3"));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] =
        gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
            {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{output.stringValue, static_cast<std::size_t>(output.nbEntries)};
    EXPECT_STRV(output_sv, "http-get-0ede9e60--");

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
    ddwaf_object_free(&output);
}

TEST(TestHttpEndpointFingerprint, UriRawConsistency)
{
    ddwaf_object tmp;

    ddwaf_object query;
    ddwaf_object_map(&query);
    ddwaf_object_map_add(&query, "Key1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&query, "key,3", ddwaf_object_invalid(&tmp));

    ddwaf_object body;
    ddwaf_object_map(&body);
    ddwaf_object_map_add(&body, "KEY1", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY2", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "KEY", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&body, "3", ddwaf_object_invalid(&tmp));

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};
    {
        ddwaf::timer deadline{2s};
        auto [output, attr] =
            gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
                {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
        EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(attr, object_store::attribute::none);

        std::string_view output_sv{output.stringValue,
            static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
        ddwaf_object_free(&output);
    }

    {
        ddwaf::timer deadline{2s};
        auto [output, attr] =
            gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever#fragment"},
                {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
        EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(attr, object_store::attribute::none);

        std::string_view output_sv{output.stringValue,
            static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
        ddwaf_object_free(&output);
    }

    {
        ddwaf::timer deadline{2s};
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/path/to/whatever?param=hello#fragment"}, {{}, {}, false, &query},
            {{}, {}, false, &body}, deadline);
        EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(attr, object_store::attribute::none);

        std::string_view output_sv{output.stringValue,
            static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
        ddwaf_object_free(&output);
    }

    {
        ddwaf::timer deadline{2s};
        auto [output, attr] =
            gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever"},
                {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
        EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(attr, object_store::attribute::none);

        std::string_view output_sv{output.stringValue,
            static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
        ddwaf_object_free(&output);
    }

    {
        ddwaf::timer deadline{2s};
        auto [output, attr] =
            gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/PaTh/To/WhAtEVER"},
                {{}, {}, false, &query}, {{}, {}, false, &body}, deadline);
        EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(attr, object_store::attribute::none);

        std::string_view output_sv{output.stringValue,
            static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
        ddwaf_object_free(&output);
    }

    ddwaf_object_free(&query);
    ddwaf_object_free(&body);
}

TEST(TestHttpHeaderFingerprint, AllKnownHeaders)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "CONNECTION", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "Accept_Encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "CONTENT-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cache-CONTROL", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "tE", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "ACCEPT_CHARSET", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "content-type", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accepT", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept_language", ddwaf_object_invalid(&tmp));

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, NoHeaders)
{
    ddwaf_object headers;
    ddwaf_object_map(&headers);

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-0000000000--0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, SomeKnownHeaders)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "referer", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-encoding", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cache-control", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-charset", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "accept-language", ddwaf_object_invalid(&tmp));

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1010101011--0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, UserAgent)
{
    ddwaf_object tmp;

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

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, ExcludedUnknownHeaders)
{
    ddwaf_object tmp;

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

    // Should be excluded
    ddwaf_object_map_add(&headers, "x-datadog-trace-id", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, UnknownHeaders)
{
    ddwaf_object tmp;

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
    ddwaf_object_map_add(&headers, "unknown_header", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "Authorization", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "WWW-Authenticate", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "Allow", ddwaf_object_invalid(&tmp));

    // Should be excluded
    ddwaf_object_map_add(&headers, "x-datadog-trace-id", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-4-47280082");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeaders)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_string(&tmp, "192.168.1.1"));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-1-1111111111");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}
TEST(TestHttpNetworkFingerprint, NoHeaders)
{
    ddwaf_object headers;
    ddwaf_object_map(&headers);

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-0-0000000000");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPs)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(
        &headers, "x-forwarded-for", ddwaf_object_string(&tmp, "192.168.1.1,::1,8.7.6.5"));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "fastly-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-3-1111111111");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersRandomChosenHeader)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "x-forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-real-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "true-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-forwarded", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "forwarded-for", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "x-cluster-client-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(
        &headers, "fastly-client-ip", ddwaf_object_string(&tmp, "192.168.1.1,::1,8.7.6.5"));
    ddwaf_object_map_add(&headers, "cf-connecting-ip", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&headers, "cf-connecting-ipv6", ddwaf_object_invalid(&tmp));

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-3-1111111111");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, HeaderPrecedence)
{
    http_network_fingerprint gen{"id", {}, {}, false, true};

    auto get_headers = [](std::size_t begin) {
        ddwaf_object tmp;
        ddwaf_object headers;
        ddwaf_object_map(&headers);

        std::array<std::string, 10> names{"x-forwarded-for", "x-real-ip", "true-client-ip",
            "x-client-ip", "x-forwarded", "forwarded-for", "x-cluster-client-ip",
            "fastly-client-ip", "cf-connecting-ip", "cf-connecting-ipv6"};

        std::string value = "::1";
        for (std::size_t i = 0; i < begin; ++i) { value += ",::1"; }

        for (std::size_t i = begin; i < names.size(); ++i) {
            ddwaf_object_map_add(
                &headers, names[i].c_str(), ddwaf_object_string(&tmp, value.c_str()));
            value += ",::1";
        }

        return headers;
    };

    auto match_frag = [&](ddwaf_object headers, const std::string &expected) {
        ddwaf::timer deadline{2s};
        auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, deadline);
        EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(attr, object_store::attribute::none);

        std::string_view output_sv{output.stringValue,
            static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
        EXPECT_STRV(output_sv, expected.c_str());

        ddwaf_object_free(&headers);
        ddwaf_object_free(&output);
    };

    match_frag(get_headers(0), "net-1-1111111111");
    match_frag(get_headers(1), "net-2-0111111111");
    match_frag(get_headers(2), "net-3-0011111111");
    match_frag(get_headers(3), "net-4-0001111111");
    match_frag(get_headers(4), "net-5-0000111111");
    match_frag(get_headers(5), "net-6-0000011111");
    match_frag(get_headers(6), "net-7-0000001111");
    match_frag(get_headers(7), "net-8-0000000111");
    match_frag(get_headers(8), "net-9-0000000011");
    match_frag(get_headers(9), "net-10-0000000001");
}

TEST(TestSessionFingerprint, UserOnly)
{
    ddwaf_object cookies;
    ddwaf_object_map(&cookies);

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl(
        {{}, {}, false, &cookies}, {{}, {}, false, {}}, {{}, {}, false, "admin"}, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn-8c6976e5---");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

TEST(TestSessionFingerprint, SessionOnly)
{
    ddwaf_object cookies;
    ddwaf_object_map(&cookies);

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl(
        {{}, {}, false, &cookies}, {{}, {}, false, "ansd0182u2n"}, {{}, {}, false, {}}, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn----269500d3");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

TEST(TestSessionFingerprint, CookiesOnly)
{
    ddwaf_object tmp;

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);
    ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
    ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
    ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
    ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
    ddwaf_object_map_add(&cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl(
        {{}, {}, false, &cookies}, {{}, {}, false, {}}, {{}, {}, false, {}}, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn--df6143bc-60ba1602-");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

TEST(TestSessionFingerprint, UserCookieAndSession)
{
    ddwaf_object tmp;

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);
    ddwaf_object_map_add(&cookies, "name", ddwaf_object_string(&tmp, "albert"));
    ddwaf_object_map_add(&cookies, "theme", ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "language", ddwaf_object_string(&tmp, "en-GB"));
    ddwaf_object_map_add(&cookies, "tracking_id", ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", ddwaf_object_string(&tmp, "yes"));
    ddwaf_object_map_add(&cookies, "session_id", ddwaf_object_string(&tmp, "ansd0182u2n"));
    ddwaf_object_map_add(&cookies, "last_visit", ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &cookies}, {{}, {}, false, "ansd0182u2n"},
        {{}, {}, false, "admin"}, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-60ba1602-269500d3");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

} // namespace
