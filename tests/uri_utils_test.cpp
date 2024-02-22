// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.hpp"
#include "uri_utils.hpp"

using namespace std::literals;

namespace {

TEST(TestURI, Complete)
{
    {
        auto uri = ddwaf::uri_parse_scheme_and_authority(
            "http+s.i-a://user@hello.com:1929/path/to/nowhere?query=none#fragment");

        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http+s.i-a");
        EXPECT_STRV(uri->authority.host, "hello.com");
        EXPECT_STRV(uri->authority.userinfo, "user");
        EXPECT_STRV(uri->authority.port, "1929");
        EXPECT_STRV(uri->authority.raw, "user@hello.com:1929");
        EXPECT_STRV(uri->raw, "http+s.i-a://user@hello.com:1929");
        EXPECT_STRV(
            uri->original, "http+s.i-a://user@hello.com:1929/path/to/nowhere?query=none#fragment");
    }

    {
        auto uri = ddwaf::uri_parse_scheme_and_authority("s://u@h:p/p?q#f");

        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "s");
        EXPECT_STRV(uri->authority.host, "h");
        EXPECT_STRV(uri->authority.userinfo, "u");
        EXPECT_STRV(uri->authority.port, "p");
        EXPECT_STRV(uri->authority.raw, "u@h:p");
    }
}

TEST(TestURI, SchemeHost)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, MalformedAuthority)
{
    std::vector<std::pair<std::string_view, std::string_view>> samples{
        {"http://auth[ority", "auth[ority"},
        {"http://something@:123", ""},
    };

    for (auto &[uri_raw, authority] : samples) {
        auto uri = ddwaf::uri_parse_scheme_and_authority(uri_raw);
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.malformed);
        EXPECT_STRV(uri->authority.host, authority.data());
    }
}

TEST(TestURI, SchemeIPv6Host)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://[200:22:11:33:44:ab:cc:bf]");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_TRUE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "200:22:11:33:44:ab:cc:bf");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeUserHost)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://paco@authority");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "paco");
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostPort)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority:1");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "1");
}

TEST(TestURI, SchemeHostQuery)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostPath)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostFragment)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostPortQuery)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority:123?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "123");
}

TEST(TestURI, SchemeHostPortPath)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority:12/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "12");
}

TEST(TestURI, SchemeHostPortFragment)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://authority:1#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "1");
}

TEST(TestURI, SchemeUserHostQuery)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://user@authority?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "user");
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeUserHostPath)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://us@authority/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "us");
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeUserHostFragment)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://u@authority#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_FALSE(uri->authority.malformed);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "u");
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, NoAuthority)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("http://");
    ASSERT_TRUE(uri);
}

TEST(TestURI, NoScheme)
{
    auto uri = ddwaf::uri_parse_scheme_and_authority("url.com");
    EXPECT_FALSE(uri);
}

} // namespace
