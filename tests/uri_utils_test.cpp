// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.hpp"
#include "uri_utils.hpp"

using namespace std::literals;

namespace {

TEST(TestURI, Scheme)
{
    {
        auto uri = ddwaf::uri_parse("http://");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_TRUE(uri->authority.raw.empty());
        EXPECT_TRUE(uri->scheme_and_authority.empty());
        EXPECT_TRUE(uri->path.empty());
        EXPECT_TRUE(uri->query.empty());
        EXPECT_TRUE(uri->fragment.empty());
    }

    {
        auto uri = ddwaf::uri_parse("http:");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_TRUE(uri->authority.raw.empty());
        EXPECT_TRUE(uri->scheme_and_authority.empty());
        EXPECT_TRUE(uri->path.empty());
        EXPECT_TRUE(uri->query.empty());
        EXPECT_TRUE(uri->fragment.empty());
    }
}

TEST(TestURI, MalformedScheme)
{
    EXPECT_FALSE(ddwaf::uri_parse("h@@:path"));
    EXPECT_FALSE(ddwaf::uri_parse("hhttp,:"));
    EXPECT_FALSE(ddwaf::uri_parse("http//"));
    EXPECT_FALSE(ddwaf::uri_parse("url.com"));
}

TEST(TestURI, SchemeAndPath)
{
    {
        auto uri = ddwaf::uri_parse("file:///usr/lib/libddwaf.so");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "file");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "/usr/lib/libddwaf.so");
        EXPECT_EQ(uri->path_index, 7);
    }

    {
        auto uri = ddwaf::uri_parse("file:/usr/lib/libddwaf.so");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "file");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "/usr/lib/libddwaf.so");
        EXPECT_EQ(uri->path_index, 5);
    }

    {
        auto uri = ddwaf::uri_parse("file:/../lib/libddwaf.so");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "file");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "/../lib/libddwaf.so");
        EXPECT_EQ(uri->path_index, 5);
    }
    {
        auto uri = ddwaf::uri_parse("file:../lib/libddwaf.so");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "file");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "../lib/libddwaf.so");
        EXPECT_EQ(uri->path_index, 5);
    }
}

TEST(TestURI, SchemeInvalidPath)
{
    EXPECT_FALSE(ddwaf::uri_parse("file:[][][]"));
    EXPECT_FALSE(ddwaf::uri_parse("file:?query"));
    EXPECT_FALSE(ddwaf::uri_parse("file:#fragment"));
}

TEST(TestURI, SchemeHost)
{
    {
        auto uri = ddwaf::uri_parse("http://authority");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
    }

    {
        auto uri = ddwaf::uri_parse("http://authority.with.dots");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_STRV(uri->authority.host, "authority.with.dots");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
    }

    {
        auto uri = ddwaf::uri_parse("h://a");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "h");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_EQ(uri->authority.host_index, 4);
        EXPECT_STRV(uri->authority.host, "a");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
    }
}

TEST(TestURI, SchemeIPv6Host)
{
    auto uri = ddwaf::uri_parse("http://[200:22:11:33:44:ab:cc:bf]");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_TRUE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "200:22:11:33:44:ab:cc:bf");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeUserHost)
{
    auto uri = ddwaf::uri_parse("http://paco@authority");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "paco");
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostPort)
{
    auto uri = ddwaf::uri_parse("http://authority:1");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "1");
}

TEST(TestURI, SchemeHostQuery)
{
    auto uri = ddwaf::uri_parse("http://authority?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->query, "query");
}

TEST(TestURI, SchemeHostPath)
{
    auto uri = ddwaf::uri_parse("http://authority/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->path, "/path");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostFragment)
{
    auto uri = ddwaf::uri_parse("http://authority#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, SchemeHostPortQuery)
{
    auto uri = ddwaf::uri_parse("http://authority:123?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "123");
    EXPECT_STRV(uri->query, "query");
}

TEST(TestURI, SchemeHostPortPath)
{
    auto uri = ddwaf::uri_parse("http://authority:12/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "12");
    EXPECT_STRV(uri->path, "/path");
}

TEST(TestURI, SchemeHostPortFragment)
{
    auto uri = ddwaf::uri_parse("http://authority:1#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "1");
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, SchemeUserHostQuery)
{
    auto uri = ddwaf::uri_parse("http://user@authority?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "user");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->query, "query");
}

TEST(TestURI, SchemeUserHostPath)
{
    auto uri = ddwaf::uri_parse("http://us@authority/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "us");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->path, "/path");
}

TEST(TestURI, SchemeUserHostFragment)
{
    auto uri = ddwaf::uri_parse("http://u@authority#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_FALSE(uri->authority.ipv6_host);
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "u");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, EmptyAuthority)
{
    {
        auto uri = ddwaf::uri_parse("http:///");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "/");
        EXPECT_TRUE(uri->fragment.empty());
    }
    {
        auto uri = ddwaf::uri_parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "urn");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "oasis:names:specification:docbook:dtd:xml:4.1.2");
        EXPECT_TRUE(uri->fragment.empty());
    }

    {
        auto uri = ddwaf::uri_parse("tel:+1-816-555-1212");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "tel");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "+1-816-555-1212");
        EXPECT_TRUE(uri->fragment.empty());
    }

    {
        auto uri = ddwaf::uri_parse("mailto:John.Doe@example.com");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "mailto");
        EXPECT_FALSE(uri->authority.ipv6_host);
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "John.Doe@example.com");
        EXPECT_TRUE(uri->fragment.empty());
    }
}

TEST(TestURI, MalformedAuthority)
{
    ASSERT_FALSE(ddwaf::uri_parse("http://host:::asdnsk"));
    ASSERT_FALSE(ddwaf::uri_parse("http://host@@@something"));
    ASSERT_FALSE(ddwaf::uri_parse("http://host:port"));
    ASSERT_FALSE(ddwaf::uri_parse("http://us@er@host:1234"));
    ASSERT_FALSE(ddwaf::uri_parse("http://user:pa]ssword@host:"));
    ASSERT_FALSE(ddwaf::uri_parse("http://[1:1::1:1"));
    ASSERT_FALSE(ddwaf::uri_parse("http://auth[ority"));
    // ASSERT_FALSE(ddwaf::uri_parse("http://something@:123"));
}

TEST(TestURI, Complete)
{
    {
        auto uri = ddwaf::uri_parse(
            "http+s.i-a://user@hello.com:1929/path/to/nowhere?query=none#fragment");

        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http+s.i-a");
        EXPECT_STRV(uri->authority.host, "hello.com");
        EXPECT_STRV(uri->authority.userinfo, "user");
        EXPECT_STRV(uri->authority.port, "1929");
        EXPECT_STRV(uri->authority.raw, "user@hello.com:1929");
        EXPECT_STRV(uri->scheme_and_authority, "http+s.i-a://user@hello.com:1929");
        EXPECT_STRV(uri->path, "/path/to/nowhere");
        EXPECT_STRV(
            uri->raw, "http+s.i-a://user@hello.com:1929/path/to/nowhere?query=none#fragment");
    }

    {
        auto uri = ddwaf::uri_parse("s://u@h:1/p?q#f");

        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "s");
        EXPECT_STRV(uri->authority.host, "h");
        EXPECT_STRV(uri->authority.userinfo, "u");
        EXPECT_STRV(uri->authority.port, "1");
        EXPECT_STRV(uri->scheme_and_authority, "s://u@h:1");
        EXPECT_STRV(uri->path, "/p");
        EXPECT_STRV(uri->authority.raw, "u@h:1");
    }
}

} // namespace
