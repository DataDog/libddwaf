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

} // namespace