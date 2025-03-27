// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "matcher/regex_match.hpp"
#include "processor/fingerprint.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestHttpEndpointFingerprint, Basic)
{
    auto query = owned_object::make_map(
        {{"Key1", owned_object{}}, {"KEY2", owned_object{}}, {"key,3", owned_object{}}});

    auto body = owned_object::make_map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = {}, .ephemeral = false, .value = "GET"},
            {.address = {},
                .key_path = {},
                .ephemeral = false,
                .value = "/path/to/whatever?param=hello"},
            {{.address = {}, .key_path = {}, .ephemeral = false, .value = object_view{query}}},
            {{.address = {}, .key_path = {}, .ephemeral = false, .value = object_view{body}}},
            cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
}

TEST(TestHttpEndpointFingerprint, EmptyQuery)
{
    auto query = owned_object::make_map();

    auto body = owned_object::make_map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
        {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
        {{{}, {}, false, object_view{body}}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60--9798c0e4");
}

TEST(TestHttpEndpointFingerprint, EmptyBody)
{

    auto query = owned_object::make_map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
    });

    auto body = owned_object::make_map();
    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
        {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
        {{{}, {}, false, object_view{body}}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");
}

TEST(TestHttpEndpointFingerprint, EmptyEverything)
{
    auto query = owned_object::make_map();
    auto body = owned_object::make_map();
    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, ""}, {{}, {}, false, ""},
        {{{}, {}, false, object_view{query}}}, {{{}, {}, false, object_view{body}}}, cache,
        deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http----");
}

TEST(TestHttpEndpointFingerprint, KeyConsistency)
{
    auto query = owned_object::make_map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key3,Key4", owned_object{}},
    });

    auto body = owned_object::make_map({
        {"KeY1", owned_object{}},
        {"kEY2", owned_object{}},
        {"KEY3", owned_object{}},
        {"KeY4", owned_object{}},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
        {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
        {{{}, {}, false, object_view{body}}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-ced401fa-ff07216e");
}

TEST(TestHttpEndpointFingerprint, InvalidQueryType)
{
    auto query = owned_object::make_array({
        "Key1",
        "KEY2",
        "key,3",
    });
    auto body = owned_object::make_map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
        {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
        {{{}, {}, false, object_view{body}}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60--9798c0e4");
}

TEST(TestHttpEndpointFingerprint, InvalidBodyType)
{
    auto query = owned_object::make_map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
    });

    auto body = owned_object::make_array({"KEY1", "KEY2", "KEY", "3"});
    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
        {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
        {{{}, {}, false, object_view{body}}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");
}

TEST(TestHttpEndpointFingerprint, InvalidQueryAndBodyType)
{

    auto query = owned_object::make_array({"Key1", "KEY2", "key,3"});
    auto body = owned_object::make_array({"KEY1", "KEY2", "KEY", "3"});
    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
        {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
        {{{}, {}, false, object_view{body}}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60--");
}

TEST(TestHttpEndpointFingerprint, UriRawConsistency)
{
    auto query = owned_object::make_map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
    });

    auto body = owned_object::make_map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};
    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
            {{{}, {}, false, object_view{body}}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/path/to/whatever#fragment"}, {{{}, {}, false, object_view{query}}},
            {{{}, {}, false, object_view{body}}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/path/to/whatever?param=hello#fragment"},
            {{{}, {}, false, object_view{query}}}, {{{}, {}, false, object_view{body}}}, cache,
            deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/path/to/whatever"}, {{{}, {}, false, object_view{query}}},
            {{{}, {}, false, object_view{body}}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/PaTh/To/WhAtEVER"}, {{{}, {}, false, object_view{query}}},
            {{{}, {}, false, object_view{body}}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }
}

TEST(TestHttpEndpointFingerprint, Regeneration)
{
    auto query = owned_object::make_map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};
    processor_cache cache;

    {
        ddwaf::timer deadline{2s};
        auto [output, attr] =
            gen.eval_impl({{}, {}, false, "GET"}, {{}, {}, false, "/path/to/whatever?param=hello"},
                {{{}, {}, false, object_view{query}}}, std::nullopt, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");
    }

    {
        auto body = owned_object::make_map({
            {"KEY1", owned_object{}},
            {"KEY2", owned_object{}},
            {"KEY", owned_object{}},
            {"3", owned_object{}},
        });

        ddwaf::timer deadline{2s};
        auto [output, attr] = gen.eval_impl({{}, {}, false, "GET"},
            {{}, {}, false, "/path/to/whatever?param=hello"}, {{{}, {}, false, object_view{query}}},
            {{{}, {}, false, object_view{body}}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }
}

TEST(TestHttpHeaderFingerprint, AllKnownHeaders)
{
    auto headers = owned_object::make_map({
        {"referer", owned_object{}},
        {"CONNECTION", owned_object{}},
        {"Accept_Encoding", owned_object{}},
        {"CONTENT-encoding", owned_object{}},
        {"cache-CONTROL", owned_object{}},
        {"tE", owned_object{}},
        {"ACCEPT_CHARSET", owned_object{}},
        {"content-type", owned_object{}},
        {"accepT", owned_object{}},
        {"accept_language", owned_object{}},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");
}

TEST(TestHttpHeaderFingerprint, NoHeaders)
{
    auto headers = owned_object::make_map();
    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-0000000000--0-");
}

TEST(TestHttpHeaderFingerprint, SomeKnownHeaders)
{
    auto headers = owned_object::make_map({
        {"referer", owned_object{}},
        {"accept-encoding", owned_object{}},
        {"cache-control", owned_object{}},
        {"accept-charset", owned_object{}},
        {"accept", owned_object{}},
        {"accept-language", owned_object{}},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1010101011--0-");
}

TEST(TestHttpHeaderFingerprint, UserAgent)
{
    auto headers = owned_object::make_map({
        {"referer", owned_object{}},
        {"connection", owned_object{}},
        {"accept-encoding", owned_object{}},
        {"content-encoding", owned_object{}},
        {"cache-control", owned_object{}},
        {"te", owned_object{}},
        {"accept-charset", owned_object{}},
        {"content-type", owned_object{}},
        {"accept", owned_object{}},
        {"accept-language", owned_object{}},
        {"user-agent", "Random"},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UserAgentAsArray)
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

    ddwaf_object ua_array;
    ddwaf_object_array(&ua_array);
    ddwaf_object_array_add(&ua_array, ddwaf_object_string(&tmp, "Random"));
    ddwaf_object_map_add(&headers, "user-agent", &ua_array);

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, UserAgentAsArrayInvalidType)
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

    ddwaf_object ua_array;
    ddwaf_object_array(&ua_array);
    ddwaf_object_array_add(&ua_array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&headers, "user-agent", &ua_array);

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, MultipleUserAgents)
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

    ddwaf_object ua_array;
    ddwaf_object_array(&ua_array);
    ddwaf_object_array_add(&ua_array, ddwaf_object_string(&tmp, "Random"));
    ddwaf_object_array_add(&ua_array, ddwaf_object_string(&tmp, "Bot"));
    ddwaf_object_map_add(&headers, "user-agent", &ua_array);

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpHeaderFingerprint, ExcludedUnknownHeaders)
{
    auto headers = owned_object::make_map({
        {"referer", owned_object{}},
        {"connection", owned_object{}},
        {"accept-encoding", owned_object{}},
        {"content-encoding", owned_object{}},
        {"cache-control", owned_object{}},
        {"te", owned_object{}},
        {"accept-charset", owned_object{}},
        {"content-type", owned_object{}},
        {"accept", owned_object{}},
        {"accept-language", owned_object{}},
        {"user-agent", "Random"},

        // Should be excluded
        {"x-datadog-trace-id", owned_object{}},
        {"x-forwarded-for", owned_object{}},
        {"x-real-ip", owned_object{}},
        {"true-client-ip", owned_object{}},
        {"x-client-ip", owned_object{}},
        {"x-forwarded", owned_object{}},
        {"forwarded-for", owned_object{}},
        {"x-cluster-client-ip", owned_object{}},
        {"fastly-client-ip", owned_object{}},
        {"cf-connecting-ip", owned_object{}},
        {"cf-connecting-ipv6", owned_object{}},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UnknownHeaders)
{
    auto headers = owned_object::make_map({
        {"referer", owned_object{}},
        {"connection", owned_object{}},
        {"accept-encoding", owned_object{}},
        {"content-encoding", owned_object{}},
        {"cache-control", owned_object{}},
        {"te", owned_object{}},
        {"accept-charset", owned_object{}},
        {"content-type", owned_object{}},
        {"accept", owned_object{}},
        {"accept-language", owned_object{}},
        {"user-agent", "Random"},
        {"unknown_header", owned_object{}},
        {"Authorization", owned_object{}},
        {"WWW-Authenticate", owned_object{}},
        {"Allow", owned_object{}},

        // Should be excluded
        {"x-datadog-trace-id", owned_object{}},
        {"x-forwarded-for", owned_object{}},
        {"x-real-ip", owned_object{}},
        {"true-client-ip", owned_object{}},
        {"x-client-ip", owned_object{}},
        {"x-forwarded", owned_object{}},
        {"forwarded-for", owned_object{}},
        {"x-cluster-client-ip", owned_object{}},
        {"fastly-client-ip", owned_object{}},
        {"cf-connecting-ip", owned_object{}},
        {"cf-connecting-ipv6", owned_object{}},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-4-47280082");
}

TEST(TestHttpHeaderFingerprint, InvalidHeaderType)
{
    owned_object headers{"value"};
    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::invalid);
    EXPECT_EQ(attr, object_store::attribute::none);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeaders)
{
    auto headers = owned_object::make_map({
        {"x-forwarded-for", "192.168.1.1"},
        {"x-real-ip", owned_object{}},
        {"true-client-ip", owned_object{}},
        {"x-client-ip", owned_object{}},
        {"x-forwarded", owned_object{}},
        {"forwarded-for", owned_object{}},
        {"x-cluster-client-ip", owned_object{}},
        {"fastly-client-ip", owned_object{}},
        {"cf-connecting-ip", owned_object{}},
        {"cf-connecting-ipv6", owned_object{}},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-1-1111111111");
}
TEST(TestHttpNetworkFingerprint, NoHeaders)
{
    auto headers = owned_object::make_map();
    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-0-0000000000");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPs)
{
    auto headers = owned_object::make_map({
        {"x-forwarded-for", "192.168.1.1,::1,8.7.6.5"},
        {"x-real-ip", owned_object{}},
        {"true-client-ip", owned_object{}},
        {"x-client-ip", owned_object{}},
        {"x-forwarded", owned_object{}},
        {"forwarded-for", owned_object{}},
        {"x-cluster-client-ip", owned_object{}},
        {"fastly-client-ip", owned_object{}},
        {"cf-connecting-ip", owned_object{}},
        {"cf-connecting-ipv6", owned_object{}},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsAsArray)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);

    ddwaf_object xff_array;
    ddwaf_object_array(&xff_array);
    ddwaf_object_array_add(&xff_array, ddwaf_object_string(&tmp, "192.168.1.1,::1,8.7.6.5"));
    ddwaf_object_map_add(&headers, "x-forwarded-for", &xff_array);
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
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-3-1111111111");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsAsArrayInvalidType)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);

    ddwaf_object xff_array;
    ddwaf_object_array(&xff_array);
    ddwaf_object_array_add(&xff_array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&headers, "x-forwarded-for", &xff_array);
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
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-0-1111111111");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsDuplicateXFF)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);

    ddwaf_object xff_array;
    ddwaf_object_array(&xff_array);
    ddwaf_object_array_add(&xff_array, ddwaf_object_string(&tmp, "192.168.1.1,::1,8.7.6.5"));
    ddwaf_object_array_add(&xff_array, ddwaf_object_string(&tmp, "192.168.1.44"));
    ddwaf_object_map_add(&headers, "x-forwarded-for", &xff_array);
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
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "net-0-1111111111");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersRandomChosenHeader)
{
    auto headers = owned_object::make_map({
        {"x-forwarded-for", owned_object{}},
        {"x-real-ip", owned_object{}},
        {"true-client-ip", owned_object{}},
        {"x-client-ip", owned_object{}},
        {"x-forwarded", owned_object{}},
        {"forwarded-for", owned_object{}},
        {"x-cluster-client-ip", owned_object{}},
        {"fastly-client-ip", "192.168.1.1,::1,8.7.6.5"},
        {"cf-connecting-ip", owned_object{}},
        {"cf-connecting-ipv6", owned_object{}},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, HeaderPrecedence)
{
    http_network_fingerprint gen{"id", {}, {}, false, true};

    auto get_headers = [](std::size_t begin) {
        auto headers = owned_object::make_map();
        std::array<std::string, 10> names{"x-forwarded-for", "x-real-ip", "true-client-ip",
            "x-client-ip", "x-forwarded", "forwarded-for", "x-cluster-client-ip",
            "fastly-client-ip", "cf-connecting-ip", "cf-connecting-ipv6"};

        std::string value = "::1";
        for (std::size_t i = 0; i < begin; ++i) { value += ",::1"; }

        for (std::size_t i = begin; i < names.size(); ++i) {
            headers.emplace(names[i], value);
            value += ",::1";
        }

        return headers;
    };

    auto match_frag = [&](owned_object headers, const std::string &expected) {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, expected.c_str());
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

TEST(TestNetworkHeaderFingerprint, InvalidHeaderType)
{
    owned_object headers{"value"};

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, object_view{headers}}, cache, deadline);
    EXPECT_EQ(output.type(), object_type::invalid);
    EXPECT_EQ(attr, object_store::attribute::none);
}

TEST(TestSessionFingerprint, UserOnly)
{
    auto cookies = owned_object::make_map();
    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, {}}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5---");
}

TEST(TestSessionFingerprint, SessionOnly)
{
    auto cookies = owned_object::make_map();
    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, {}}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn----269500d3");
}

TEST(TestSessionFingerprint, CookiesOnly)
{
    auto cookies = owned_object::make_map({
        {"name", "albert"},
        {"theme", "dark"},
        {"language", "en-GB"},
        {"tracking_id", "xyzabc"},
        {"gdpr_consent", "yes"},
        {"session_id", "ansd0182u2n"},
        {"last_visit", "2024-07-16T12:00:00Z"},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, {}}}, {{{}, {}, false, {}}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn--df6143bc-60ba1602-");
}

TEST(TestSessionFingerprint, UserCookieAndSession)
{
    auto cookies = owned_object::make_map({
        {"name", "albert"},
        {"theme", "dark"},
        {"language", "en-GB"},
        {"tracking_id", "xyzabc"},
        {"gdpr_consent", "yes"},
        {"session_id", "ansd0182u2n"},
        {"last_visit", "2024-07-16T12:00:00Z"},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-60ba1602-269500d3");
}

TEST(TestSessionFingerprint, CookieKeysNormalization)
{
    auto cookies = owned_object::make_map({
        {"nAmE", "albert"},
        {"THEME", "dark"},
        {"language,ID", "en-GB"},
        {"tra,cKing,ID", "xyzabc"},
        {"Gdpr_consent", "yes"},
        {"SESSION_ID", "ansd0182u2n"},
        {"last_visiT", "2024-07-16T12:00:00Z"},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-424e7e09-60ba1602-269500d3");
}

TEST(TestSessionFingerprint, CookieValuesNormalization)
{
    auto cookies = owned_object::make_map({
        {"name", "albert,martinez"},
        {"theme", "dark"},
        {"language", "en-GB,en-US"},
        {"tracking_id", "xyzabc"},
        {"gdpr_consent", ",yes"},
        {"session_id", "ansd0182u2n,"},
        {"last_visit", "2024-07-16T12:00:00Z"},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-64f82cf7-269500d3");
}

TEST(TestSessionFingerprint, CookieValuesAsArray)
{
    ddwaf_object tmp;

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "albert,martinez"));
    ddwaf_object_map_add(&cookies, "name", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "theme", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "en-GB,en-US"));
    ddwaf_object_map_add(&cookies, "language", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "tracking_id", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, ",yes"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "ansd0182u2n,"));
    ddwaf_object_map_add(&cookies, "session_id", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));
    ddwaf_object_map_add(&cookies, "last_visit", &array);

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, &cookies}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-64f82cf7-269500d3");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

TEST(TestSessionFingerprint, CookieValuesAsArrayInvalidType)
{
    ddwaf_object tmp;

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "name", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "theme", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "language", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "tracking_id", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "gdpr_consent", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "session_id", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 42));
    ddwaf_object_map_add(&cookies, "last_visit", &array);

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, &cookies}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-d3648ef2-269500d3");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

TEST(TestSessionFingerprint, CookieValuesArrayMultiples)
{
    ddwaf_object tmp;

    ddwaf_object cookies;
    ddwaf_object_map(&cookies);

    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "albert,martinez"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "albert,martinez"));
    ddwaf_object_map_add(&cookies, "name", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "dark"));
    ddwaf_object_map_add(&cookies, "theme", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "en-GB,en-US"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "en-GB,en-US"));
    ddwaf_object_map_add(&cookies, "language", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "xyzabc"));
    ddwaf_object_map_add(&cookies, "tracking_id", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, ",yes"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, ",yes"));
    ddwaf_object_map_add(&cookies, "gdpr_consent", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "ansd0182u2n,"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "ansd0182u2n,"));
    ddwaf_object_map_add(&cookies, "session_id", &array);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "2024-07-16T12:00:00Z"));
    ddwaf_object_map_add(&cookies, "last_visit", &array);

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, &cookies}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(attr, object_store::attribute::none);

    std::string_view output_sv{
        output.stringValue, static_cast<std::size_t>(static_cast<std::size_t>(output.nbEntries))};
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-d3648ef2-269500d3");

    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);
}

TEST(TestSessionFingerprint, CookieEmptyValues)
{
    auto cookies = owned_object::make_map({
        {"name", owned_object{}},
        {"theme", owned_object{}},
        {"language", owned_object{}},
        {"tracking_id", owned_object{}},
        {"gdpr_consent", owned_object{}},
        {"session_id", owned_object{}},
        {"last_visit", owned_object{}},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-d3648ef2-269500d3");
}

TEST(TestSessionFingerprint, CookieEmptyKeys)
{
    auto cookies = owned_object::make_map({
        {"", "albert,martinez"},
        {"", "dark"},
        {"", "en-GB,en-US"},
        {"", "xyzabc"},
        {"", ",yes"},
        {"", "ansd0182u2n,"},
        {"", "2024-07-16T12:00:00Z"},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, "ansd0182u2n"}}, {{{}, {}, false, "admin"}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-d3648ef2-f32e5c3e-269500d3");
}

TEST(TestSessionFingerprint, EmptyEverything)
{
    auto cookies = owned_object::make_map();
    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{{}, {}, false, object_view{cookies}}},
        {{{}, {}, false, {}}}, {{{}, {}, false, {}}}, cache, deadline);

    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(attr, object_store::attribute::none);

    auto output_sv = object_view{output}.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn----");
}

TEST(TestSessionFingerprint, Regeneration)
{
    session_fingerprint gen{"id", {}, {}, false, true};
    processor_cache cache;

    {
        ddwaf::timer deadline{2s};
        auto [output, attr] =
            gen.eval_impl(std::nullopt, std::nullopt, std::nullopt, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn----");
    }

    {
        auto cookies = owned_object::make_map({
            {"name", "albert,martinez"},
            {"theme", "dark"},
            {"language", "en-GB,en-US"},
            {"tracking_id", "xyzabc"},
            {"gdpr_consent", ",yes"},
            {"session_id", "ansd0182u2n,"},
            {"last_visit", "2024-07-16T12:00:00Z"},
        });

        ddwaf::timer deadline{2s};

        auto [output, attr] = gen.eval_impl(
            {{{}, {}, false, object_view{cookies}}}, std::nullopt, std::nullopt, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn--df6143bc-64f82cf7-");
    }

    {
        ddwaf::timer deadline{2s};

        auto [output, attr] = gen.eval_impl(
            std::nullopt, {{{}, {}, false, "ansd0182u2n"}}, std::nullopt, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn--df6143bc-64f82cf7-269500d3");
    }

    {
        ddwaf::timer deadline{2s};

        auto [output, attr] =
            gen.eval_impl(std::nullopt, std::nullopt, {{{}, {}, false, "user"}}, cache, deadline);
        EXPECT_EQ(output.type(), object_type::string);
        EXPECT_EQ(attr, object_store::attribute::none);

        auto output_sv = object_view{output}.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn-04f8996d-df6143bc-64f82cf7-269500d3");
    }
}

} // namespace
