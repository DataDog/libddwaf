// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "processor/fingerprint.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestHttpEndpointFingerprint, Basic)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map({{"Key1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"key,3", ddwaf::test::ddwaf_object_da::make_uninit()}});

    auto body = object_builder_da::map({
        {"KEY1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"3", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
        {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
        {{.address = {}, .key_path = {}, .value = {query}}},
        {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
}

TEST(TestHttpEndpointFingerprint, EmptyQuery)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map();

    auto body = object_builder_da::map({
        {"KEY1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"3", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
        {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
        {{.address = {}, .key_path = {}, .value = {query}}},
        {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60--9798c0e4");
}

TEST(TestHttpEndpointFingerprint, EmptyBody)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map({
        {"Key1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"key,3", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    auto body = object_builder_da::map();
    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
        {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
        {{.address = {}, .key_path = {}, .value = {query}}},
        {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");
}

TEST(TestHttpEndpointFingerprint, EmptyEverything)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map();
    auto body = object_builder_da::map();
    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = ""},
        {.address = {}, .key_path = {}, .value = ""},
        {{.address = {}, .key_path = {}, .value = {query}}},
        {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "http----");
}

TEST(TestHttpEndpointFingerprint, KeyConsistency)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map({
        {"Key1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"key3,Key4", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    auto body = object_builder_da::map({
        {"KeY1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"kEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY3", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KeY4", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
        {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
        {{.address = {}, .key_path = {}, .value = {query}}},
        {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "http-get-0ede9e60-ced401fa-ff07216e");
}

TEST(TestHttpEndpointFingerprint, UriRawConsistency)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map({
        {"Key1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"key,3", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    auto body = object_builder_da::map({
        {"KEY1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"3", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};
    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
            {{.address = {}, .key_path = {}, .value = {query}}},
            {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {}, .key_path = {}, .value = "/path/to/whatever#fragment"},
            {{.address = {}, .key_path = {}, .value = {query}}},
            {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {},
                .key_path = {},

                .value = "/path/to/whatever?param=hello#fragment"},
            {{.address = {}, .key_path = {}, .value = {query}}},
            {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {}, .key_path = {}, .value = "/path/to/whatever"},
            {{.address = {}, .key_path = {}, .value = {query}}},
            {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }

    {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {}, .key_path = {}, .value = "/PaTh/To/WhAtEVER"},
            {{.address = {}, .key_path = {}, .value = {query}}},
            {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }
}

TEST(TestHttpEndpointFingerprint, Regeneration)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder_da::map({
        {"Key1", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"key,3", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_endpoint_fingerprint gen{"id", {}, {}, false, true};
    processor_cache cache;

    {
        ddwaf::timer deadline{2s};
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
            {{.address = {}, .key_path = {}, .value = {query}}}, std::nullopt, cache, alloc,
            deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-");
    }

    {
        auto body = object_builder_da::map({
            {"KEY1", ddwaf::test::ddwaf_object_da::make_uninit()},
            {"KEY2", ddwaf::test::ddwaf_object_da::make_uninit()},
            {"KEY", ddwaf::test::ddwaf_object_da::make_uninit()},
            {"3", ddwaf::test::ddwaf_object_da::make_uninit()},
        });

        ddwaf::timer deadline{2s};
        auto output = gen.eval_impl({.address = {}, .key_path = {}, .value = "GET"},
            {.address = {}, .key_path = {}, .value = "/path/to/whatever?param=hello"},
            {{.address = {}, .key_path = {}, .value = {query}}},
            {{.address = {}, .key_path = {}, .value = {body}}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "http-get-0ede9e60-0ac3796a-9798c0e4");
    }
}

TEST(TestHttpHeaderFingerprint, AllKnownHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"CONNECTION", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"Accept_Encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"CONTENT-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-CONTROL", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"tE", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"ACCEPT_CHARSET", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accepT", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept_language", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");
}

TEST(TestHttpHeaderFingerprint, NoHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map();
    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-0000000000--0-");
}

TEST(TestHttpHeaderFingerprint, SomeKnownHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1010101011--0-");
}

TEST(TestHttpHeaderFingerprint, UserAgent)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"connection", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"te", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"user-agent", "Random"},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UserAgentAsArray)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"connection", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"te", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"user-agent", object_builder_da::array({"Random"})},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UserAgentAsArrayInvalidType)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"connection", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"te", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"user-agent", object_builder_da::array({42})},
    });
    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");
}

TEST(TestHttpHeaderFingerprint, MultipleUserAgents)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"connection", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"te", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"user-agent", object_builder_da::array({"Random", "Bot"})},
    });
    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");
}

TEST(TestHttpHeaderFingerprint, ExcludedUnknownHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"connection", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"te", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"user-agent", "Random"},

        // Should be excluded
        {"x-datadog-trace-id", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UnknownHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"referer", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"connection", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-encoding", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cache-control", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"te", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-charset", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"content-type", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"accept-language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"user-agent", "Random"},
        {"unknown_header", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"Authorization", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"WWW-Authenticate", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"Allow", ddwaf::test::ddwaf_object_da::make_uninit()},

        // Should be excluded
        {"x-datadog-trace-id", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_header_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-4-47280082");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"x-forwarded-for", "192.168.1.1"},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-1-1111111111");
}
TEST(TestHttpNetworkFingerprint, NoHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map();
    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-0-0000000000");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPs)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"x-forwarded-for", "192.168.1.1,::1,8.7.6.5"},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsAsArray)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"x-forwarded-for", object_builder_da::array({"192.168.1.1,::1,8.7.6.5"})},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });
    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsAsArrayInvalidType)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"x-forwarded-for", object_builder_da::array({42})},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-0-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsDuplicateXFF)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"x-forwarded-for", object_builder_da::array({"192.168.1.1,::1,8.7.6.5", "192.168.1.44"})},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-0-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersRandomChosenHeader)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder_da::map({
        {"x-forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-real-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"true-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-forwarded", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"forwarded-for", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"x-cluster-client-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"fastly-client-ip", "192.168.1.1,::1,8.7.6.5"},
        {"cf-connecting-ip", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"cf-connecting-ipv6", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, HeaderPrecedence)
{
    auto *alloc = memory::get_default_resource();

    http_network_fingerprint gen{"id", {}, {}, false, true};

    auto get_headers = [](std::size_t begin) {
        auto headers = object_builder_da::map();
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
        auto output = gen.eval_impl(
            {.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, expected);
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
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map();
    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = {}}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5---");
}

TEST(TestSessionFingerprint, SessionOnly)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map();
    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = {}}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn----269500d3");
}

TEST(TestSessionFingerprint, CookiesOnly)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
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
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = {}}},
        {{.address = {}, .key_path = {}, .value = {}}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn--df6143bc-60ba1602-");
}

TEST(TestSessionFingerprint, UserCookieAndSession)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
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
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-60ba1602-269500d3");
}

TEST(TestSessionFingerprint, CookieKeysNormalization)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
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
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-424e7e09-60ba1602-269500d3");
}

TEST(TestSessionFingerprint, CookieValuesNormalization)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
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
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-64f82cf7-269500d3");
}

TEST(TestSessionFingerprint, CookieValuesAsArray)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
        {"name", object_builder_da::array({"albert,martinez"})},
        {"theme", object_builder_da::array({"dark"})},
        {"language", object_builder_da::array({"en-GB,en-US"})},
        {"tracking_id", object_builder_da::array({"xyzabc"})},
        {"gdpr_consent", object_builder_da::array({",yes"})},
        {"session_id", object_builder_da::array({"ansd0182u2n,"})},
        {"last_visit", object_builder_da::array({"2024-07-16T12:00:00Z"})},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-64f82cf7-269500d3");
}

TEST(TestSessionFingerprint, CookieValuesAsArrayInvalidType)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
        {"name", object_builder_da::array({42})},
        {"theme", object_builder_da::array({42})},
        {"language", object_builder_da::array({42})},
        {"tracking_id", object_builder_da::array({42})},
        {"gdpr_consent", object_builder_da::array({42})},
        {"session_id", object_builder_da::array({42})},
        {"last_visit", object_builder_da::array({42})},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-d3648ef2-269500d3");
}

TEST(TestSessionFingerprint, CookieValuesArrayMultiples)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
        {"name", object_builder_da::array({"albert,martinez", "albert,martinez"})},
        {"theme", object_builder_da::array({"dark", "dark"})},
        {"language", object_builder_da::array({"en-GB,en-US", "en-GB,en-US"})},
        {"tracking_id", object_builder_da::array({"xyzabc", "xyzabc"})},
        {"gdpr_consent", object_builder_da::array({",yes", ",yes"})},
        {"session_id", object_builder_da::array({"ansd0182u2n,", "ansd0182u2n,"})},
        {"last_visit", object_builder_da::array({"2024-07-16T12:00:00Z", "2024-07-16T12:00:00Z"})},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-d3648ef2-269500d3");
}

TEST(TestSessionFingerprint, CookieEmptyValues)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
        {"name", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"theme", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"language", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"tracking_id", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"gdpr_consent", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"session_id", ddwaf::test::ddwaf_object_da::make_uninit()},
        {"last_visit", ddwaf::test::ddwaf_object_da::make_uninit()},
    });

    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-df6143bc-d3648ef2-269500d3");
}

TEST(TestSessionFingerprint, CookieEmptyKeys)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map({
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
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
        {{.address = {}, .key_path = {}, .value = "admin"}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn-8c6976e5-d3648ef2-f32e5c3e-269500d3");
}

TEST(TestSessionFingerprint, EmptyEverything)
{
    auto *alloc = memory::get_default_resource();

    auto cookies = object_builder_da::map();
    session_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
        {{.address = {}, .key_path = {}, .value = {}}},
        {{.address = {}, .key_path = {}, .value = {}}}, cache, alloc, deadline);

    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "ssn----");
}

TEST(TestSessionFingerprint, Regeneration)
{
    auto *alloc = memory::get_default_resource();

    session_fingerprint gen{"id", {}, {}, false, true};
    processor_cache cache;

    {
        ddwaf::timer deadline{2s};
        auto output =
            gen.eval_impl(std::nullopt, std::nullopt, std::nullopt, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn----");
    }

    {
        auto cookies = object_builder_da::map({
            {"name", "albert,martinez"},
            {"theme", "dark"},
            {"language", "en-GB,en-US"},
            {"tracking_id", "xyzabc"},
            {"gdpr_consent", ",yes"},
            {"session_id", "ansd0182u2n,"},
            {"last_visit", "2024-07-16T12:00:00Z"},
        });

        ddwaf::timer deadline{2s};

        auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = {cookies}}},
            std::nullopt, std::nullopt, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn--df6143bc-64f82cf7-");
    }

    {
        ddwaf::timer deadline{2s};

        auto output =
            gen.eval_impl(std::nullopt, {{.address = {}, .key_path = {}, .value = "ansd0182u2n"}},
                std::nullopt, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn--df6143bc-64f82cf7-269500d3");
    }

    {
        ddwaf::timer deadline{2s};

        auto output = gen.eval_impl(std::nullopt, std::nullopt,
            {{.address = {}, .key_path = {}, .value = "user"}}, cache, alloc, deadline);
        EXPECT_TRUE(output.is_string());

        auto output_sv = output.as<std::string_view>();
        EXPECT_STRV(output_sv, "ssn-04f8996d-df6143bc-64f82cf7-269500d3");
    }
}

} // namespace
