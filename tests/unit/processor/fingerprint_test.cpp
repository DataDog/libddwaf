// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "processor/fingerprint.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestHttpEndpointFingerprint, Basic)
{
    auto *alloc = memory::get_default_resource();

    auto query = object_builder::map(
        {{"Key1", owned_object{}}, {"KEY2", owned_object{}}, {"key,3", owned_object{}}});

    auto body = object_builder::map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
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

    auto query = object_builder::map();

    auto body = object_builder::map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
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

    auto query = object_builder::map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
    });

    auto body = object_builder::map();
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

    auto query = object_builder::map();
    auto body = object_builder::map();
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

    auto query = object_builder::map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key3,Key4", owned_object{}},
    });

    auto body = object_builder::map({
        {"KeY1", owned_object{}},
        {"kEY2", owned_object{}},
        {"KEY3", owned_object{}},
        {"KeY4", owned_object{}},
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

    auto query = object_builder::map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
    });

    auto body = object_builder::map({
        {"KEY1", owned_object{}},
        {"KEY2", owned_object{}},
        {"KEY", owned_object{}},
        {"3", owned_object{}},
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

    auto query = object_builder::map({
        {"Key1", owned_object{}},
        {"KEY2", owned_object{}},
        {"key,3", owned_object{}},
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
        auto body = object_builder::map({
            {"KEY1", owned_object{}},
            {"KEY2", owned_object{}},
            {"KEY", owned_object{}},
            {"3", owned_object{}},
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

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111--0-");
}

TEST(TestHttpHeaderFingerprint, NoHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map();
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

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1010101011--0-");
}

TEST(TestHttpHeaderFingerprint, UserAgent)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UserAgentAsArray)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
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
        {"user-agent", object_builder::array({"Random"})},
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

    auto headers = object_builder::map({
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
        {"user-agent", object_builder::array({42})},
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

    auto headers = object_builder::map({
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
        {"user-agent", object_builder::array({"Random", "Bot"})},
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

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-0-");
}

TEST(TestHttpHeaderFingerprint, UnknownHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "hdr-1111111111-a441b15f-4-47280082");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-1-1111111111");
}
TEST(TestHttpNetworkFingerprint, NoHeaders)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map();
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

    auto headers = object_builder::map({
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsAsArray)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
        {"x-forwarded-for", object_builder::array({"192.168.1.1,::1,8.7.6.5"})},
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-3-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsAsArrayInvalidType)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
        {"x-forwarded-for", object_builder::array({42})},
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-0-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersMultipleChosenIPsDuplicateXFF)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
        {"x-forwarded-for", object_builder::array({"192.168.1.1,::1,8.7.6.5", "192.168.1.44"})},
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
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {headers}}, cache, alloc, deadline);
    EXPECT_TRUE(output.is_string());

    auto output_sv = output.as<std::string_view>();
    EXPECT_STRV(output_sv, "net-0-1111111111");
}

TEST(TestHttpNetworkFingerprint, AllXFFHeadersRandomChosenHeader)
{
    auto *alloc = memory::get_default_resource();

    auto headers = object_builder::map({
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
        auto headers = object_builder::map();
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

    auto cookies = object_builder::map();
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

    auto cookies = object_builder::map();
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

    auto cookies = object_builder::map({
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

    auto cookies = object_builder::map({
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

    auto cookies = object_builder::map({
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

    auto cookies = object_builder::map({
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

    auto cookies = object_builder::map({
        {"name", object_builder::array({"albert,martinez"})},
        {"theme", object_builder::array({"dark"})},
        {"language", object_builder::array({"en-GB,en-US"})},
        {"tracking_id", object_builder::array({"xyzabc"})},
        {"gdpr_consent", object_builder::array({",yes"})},
        {"session_id", object_builder::array({"ansd0182u2n,"})},
        {"last_visit", object_builder::array({"2024-07-16T12:00:00Z"})},
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

    auto cookies = object_builder::map({
        {"name", object_builder::array({42})},
        {"theme", object_builder::array({42})},
        {"language", object_builder::array({42})},
        {"tracking_id", object_builder::array({42})},
        {"gdpr_consent", object_builder::array({42})},
        {"session_id", object_builder::array({42})},
        {"last_visit", object_builder::array({42})},
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

    auto cookies = object_builder::map({
        {"name", object_builder::array({"albert,martinez", "albert,martinez"})},
        {"theme", object_builder::array({"dark", "dark"})},
        {"language", object_builder::array({"en-GB,en-US", "en-GB,en-US"})},
        {"tracking_id", object_builder::array({"xyzabc", "xyzabc"})},
        {"gdpr_consent", object_builder::array({",yes", ",yes"})},
        {"session_id", object_builder::array({"ansd0182u2n,", "ansd0182u2n,"})},
        {"last_visit", object_builder::array({"2024-07-16T12:00:00Z", "2024-07-16T12:00:00Z"})},
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

    auto cookies = object_builder::map({
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

    auto cookies = object_builder::map({
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

    auto cookies = object_builder::map();
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
        auto cookies = object_builder::map({
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
