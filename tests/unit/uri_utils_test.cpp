// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "uri_utils.hpp"

#include "common/gtest_utils.hpp"

using namespace std::literals;

namespace {

TEST(TestURI, Scheme)
{
    {
        auto uri = ddwaf::uri_parse("http://");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
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
    EXPECT_FALSE(ddwaf::uri_parse("@http"));
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
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "../lib/libddwaf.so");
        EXPECT_EQ(uri->path_index, 5);
    }

    {
        auto uri = ddwaf::uri_parse("http:///");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
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
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->path, "John.Doe@example.com");
        EXPECT_TRUE(uri->fragment.empty());
    }
}

TEST(TestURI, SchemeMalformedPath) { EXPECT_FALSE(ddwaf::uri_parse("file:[][][]")); }

TEST(TestURI, SchemeHost)
{
    {
        auto uri = ddwaf::uri_parse("http://authority");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
    }

    {
        auto uri = ddwaf::uri_parse("http://authority.with.dots");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority.with.dots");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
    }

    {
        auto uri = ddwaf::uri_parse("h://a");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "h");
        EXPECT_EQ(uri->authority.host_index, 4);
        EXPECT_STRV(uri->authority.host, "a");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
    }
}

TEST(TestURI, SchemeQuery)
{
    auto uri = ddwaf::uri_parse("http:?hello&other=whatever&array[]=something&bye=");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->query, "hello&other=whatever&array[]=something&bye=");
}

TEST(TestURI, SchemeFragment)
{
    auto uri = ddwaf::uri_parse("http:#hello");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->fragment, "hello");
}

TEST(TestURI, SchemeQueryFragment)
{
    auto uri = ddwaf::uri_parse("http:?hello#bye");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->query, "hello");
    EXPECT_STRV(uri->fragment, "bye");
}

TEST(TestURI, SchemeIPv4Host)
{
    auto uri = ddwaf::uri_parse("http://1.2.3.4");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "1.2.3.4");
    EXPECT_TRUE(uri->authority.host_ip);
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeIPv6Host)
{
    auto uri = ddwaf::uri_parse("http://[200:22:11:33:44:ab:cc:bf]");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "200:22:11:33:44:ab:cc:bf");
    EXPECT_TRUE(uri->authority.host_ip);
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeIPv6HostPort)
{
    auto uri = ddwaf::uri_parse("http://[200:22:11:33:44:ab:cc:bf]:1234");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "200:22:11:33:44:ab:cc:bf");
    EXPECT_TRUE(uri->authority.host_ip);
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "1234");
}

TEST(TestURI, SchemeMalformedIPv6Host)
{
    ASSERT_FALSE(ddwaf::uri_parse("http://[200:::::::::::::::::1]"));
}

TEST(TestURI, SchemeUser)
{
    {
        auto uri = ddwaf::uri_parse("http://paco@");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_STRV(uri->authority.userinfo, "paco");
        EXPECT_TRUE(uri->authority.port.empty());
    }

    {
        auto uri = ddwaf::uri_parse("http://paco@:");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_STRV(uri->authority.userinfo, "paco");
        EXPECT_TRUE(uri->authority.port.empty());
    }
}

TEST(TestURI, SchemeUserPort)
{
    {
        auto uri = ddwaf::uri_parse("http://paco@:1919");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_STRV(uri->authority.userinfo, "paco");
        EXPECT_EQ(uri->authority.port, "1919");
    }
}

TEST(TestURI, SchemeUserHost)
{
    {
        auto uri = ddwaf::uri_parse("http://paco@authority");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_STRV(uri->authority.userinfo, "paco");
        EXPECT_TRUE(uri->authority.port.empty());
    }
}

TEST(TestURI, SchemeUserHostPort)
{
    {
        auto uri = ddwaf::uri_parse("http://paco@authority:1919");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_STRV(uri->authority.userinfo, "paco");
        EXPECT_EQ(uri->authority.port, "1919");
    }
}

TEST(TestURI, SchemeHostPort)
{
    {
        auto uri = ddwaf::uri_parse("http://authority:1");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_STRV(uri->authority.port, "1");
    }

    {
        // Empty host
        auto uri = ddwaf::uri_parse("h://:19283");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "h");
        EXPECT_TRUE(uri->authority.host.empty());
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_STRV(uri->authority.port, "19283");
    }

    {
        // Empty host
        ASSERT_FALSE(ddwaf::uri_parse("h://:65536"));
        ASSERT_FALSE(ddwaf::uri_parse("h://:-1"));
    }
}

TEST(TestURI, MalformedPort)
{
    ASSERT_FALSE(ddwaf::uri_parse("h://:65536"));
    ASSERT_FALSE(ddwaf::uri_parse("h://:123123123"));
    ASSERT_FALSE(ddwaf::uri_parse("h://:-1"));
}

TEST(TestURI, SchemeHostQuery)
{
    {
        auto uri = ddwaf::uri_parse("http://authority?query");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->query, "query");
    }

    {
        auto uri = ddwaf::uri_parse("http://authority:?query");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->query, "query");
    }

    {
        auto uri = ddwaf::uri_parse("http://authority:?q@uery");
        ASSERT_TRUE(uri);
        EXPECT_STRV(uri->scheme, "http");
        EXPECT_STRV(uri->authority.host, "authority");
        EXPECT_TRUE(uri->authority.userinfo.empty());
        EXPECT_TRUE(uri->authority.port.empty());
        EXPECT_STRV(uri->query, "q@uery");
    }
}

TEST(TestURI, SchemeHostMalformedQuery)
{
    ASSERT_FALSE(ddwaf::uri_parse("http://authority?que<>ry"));
}

TEST(TestURI, SchemeHostPath)
{
    auto uri = ddwaf::uri_parse("http://authority/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->path, "/path");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
}

TEST(TestURI, SchemeHostMalformedPath)
{
    ASSERT_FALSE(ddwaf::uri_parse("http://authority/pa[]th"));
}

TEST(TestURI, SchemeHostFragment)
{
    auto uri = ddwaf::uri_parse("http://authority#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, SchemeHostMalformedFragment)
{
    ASSERT_FALSE(ddwaf::uri_parse("http://authority#f[]"));
}

TEST(TestURI, SchemeHostPortQuery)
{
    auto uri = ddwaf::uri_parse("http://authority:123?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "http");
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
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "u");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->fragment, "f");
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

TEST(TestURI, RelativeRefHostPortQuery)
{
    auto uri = ddwaf::uri_parse("//authority:123?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "123");
    EXPECT_STRV(uri->query, "query");
}

TEST(TestURI, RelativeRefHostPortPath)
{
    auto uri = ddwaf::uri_parse("//authority:12/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "12");
    EXPECT_STRV(uri->path, "/path");
}

TEST(TestURI, RelativeRefHostPortFragment)
{
    auto uri = ddwaf::uri_parse("//authority:1#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "1");
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, RelativeRefUserHostQuery)
{
    auto uri = ddwaf::uri_parse("//user@authority?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "user");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->query, "query");
}

TEST(TestURI, RelativeRefUserHostPath)
{
    auto uri = ddwaf::uri_parse("//us@authority/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "us");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->path, "/path");
}

TEST(TestURI, RelativeRefUserHostFragment)
{
    auto uri = ddwaf::uri_parse("//u@authority#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "authority");
    EXPECT_STRV(uri->authority.userinfo, "u");
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, RelativeRefAbsolutePath)
{
    auto uri = ddwaf::uri_parse("/path");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "");
    EXPECT_STRV(uri->path, "/path");
}

TEST(TestURI, RelativeRefAbsolutePathFragment)
{
    auto uri = ddwaf::uri_parse("/path#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "");
    EXPECT_STRV(uri->path, "/path");
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, RelativeRefAbsolutePathQuery)
{
    auto uri = ddwaf::uri_parse("/path?query");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "");
    EXPECT_STRV(uri->path, "/path");
    EXPECT_STRV(uri->query, "query");
}

TEST(TestURI, RelativeRefAbsolutePathQueryFragment)
{
    auto uri = ddwaf::uri_parse("/path?query#f");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_STRV(uri->authority.port, "");
    EXPECT_STRV(uri->path, "/path");
    EXPECT_STRV(uri->query, "query");
    EXPECT_STRV(uri->fragment, "f");
}

TEST(TestURI, RelativeRefQuery)
{
    auto uri = ddwaf::uri_parse("/?hello");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->path, "/");
    EXPECT_STRV(uri->query, "hello");
}

TEST(TestURI, RelativeRefFragment)
{
    auto uri = ddwaf::uri_parse("/#hello");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->path, "/");
    EXPECT_STRV(uri->fragment, "hello");
}

TEST(TestURI, RelativeRefQueryFragment)
{
    auto uri = ddwaf::uri_parse("/?hello#bye");
    ASSERT_TRUE(uri);
    EXPECT_STRV(uri->scheme, "");
    EXPECT_STRV(uri->authority.host, "");
    EXPECT_TRUE(uri->authority.userinfo.empty());
    EXPECT_TRUE(uri->authority.port.empty());
    EXPECT_STRV(uri->path, "/");
    EXPECT_STRV(uri->query, "hello");
    EXPECT_STRV(uri->fragment, "bye");
}

} // namespace
