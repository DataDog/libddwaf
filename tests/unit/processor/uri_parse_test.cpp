// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "processor/uri_parse.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestUriParseProcessor, QueryParameters)
{
    auto *alloc = memory::get_default_resource();

    std::vector<std::pair<std::string, std::string>> samples = {
        {"https://datadoghq.com/?query", R"({"query": true})"},
        {"https://datadoghq.com/?query&flag&other",
            R"({"query": true, "flag": true, "other": true})"},
        {"https://datadoghq.com/?query&other=value", R"({"query": true,"other":"value"})"},
        {"https://datadoghq.com/?other=value&query", R"({"query": true,"other":"value"})"},
        {"https://datadoghq.com/?query=", R"({"query": ""})"},
        {"https://datadoghq.com/?query=&other=", R"({"query": "", "other": ""})"},
        {"https://datadoghq.com/?query=&other=value", R"({"query": "","other":"value"})"},
        {"https://datadoghq.com/?other=value&query=", R"({"query": "","other":"value"})"},
        {"https://datadoghq.com/?query=value", R"({"query": "value"})"},
        {"https://datadoghq.com/?query=value&other=something",
            R"({"query":"value","other":"something"})"},
        {"https://datadoghq.com/?query=value&query=something",
            R"({"query":["value","something"]})"},
        {"https://datadoghq.com/?query=value&other=whatever&query=something",
            R"({"query":["value","something"],"other":"whatever"})"},
        {"https://datadoghq.com/?query[]=value&query[]=something",
            R"({"query":["value","something"]})"},
        {"https://datadoghq.com/?query[]=value&other=whatever&query[]=something",
            R"({"query":["value","something"],"other":"whatever"})"},
        {"https://datadoghq.com/?query[]=value&other=whatever&query[]=something&other=whatever",
            R"({"query":["value","something"],"other":["whatever", "whatever"]})"},
        {"https://datadoghq.com/?query[0]=value&query[1]=something",
            R"({"query[0]":"value","query[1]":"something"})"},
    };

    uri_parse_processor gen{"id", {}, {}, false, true};

    for (auto &[url, result] : samples) {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl(
            {.address = {}, .key_path = {}, .scope = evaluation_scope::context, .value = url},
            cache, alloc, deadline);
        EXPECT_TRUE(output.is_map());
        EXPECT_EQ(attr, evaluation_scope::context);

        auto query = object_view{output}.find("query");
        EXPECT_JSON(query.ref(), result);
    }
}

TEST(TestUriParseProcessor, MixedUrls)
{
    auto *alloc = memory::get_default_resource();

    std::vector<std::pair<std::string, std::string>> samples = {
        {"https://",
            R"({"scheme":"https","userinfo":"","host":"","port":0,"path":"","query":{},"fragment":""})"},
        {"ftp://",
            R"({"scheme":"ftp","userinfo":"","host":"","port":0,"path":"","query":{},"fragment":""})"},
        {"https://user@test.com:222/"
         "path?query=value1&query=value2&flag&emptyvalue=&array[]=1&array[]=2&normal=value#frag",
            R"({"scheme":"https","userinfo":"user","host":"test.com","port":222,"path":"/path","query":{"normal":"value","array":["1","2"],"emptyvalue":"","flag":true,"query":["value1","value2"]},"fragment":"frag"})"},
    };

    uri_parse_processor gen{"id", {}, {}, false, true};

    for (auto &[url, result] : samples) {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl(
            {.address = {}, .key_path = {}, .scope = evaluation_scope::context, .value = url},
            cache, alloc, deadline);
        EXPECT_TRUE(output.is_map());
        EXPECT_EQ(attr, evaluation_scope::context);

        EXPECT_JSON(output.ref(), result);
    }
}

TEST(TestUriParseProcessor, Subcontext)
{
    auto *alloc = memory::get_default_resource();

    std::string_view url =
        "https://user@test.com:222/"
        "path?query=value1&query=value2&flag&emptyvalue=&array[]=1&array[]=2&normal=value#frag";

    uri_parse_processor gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl(
        {.address = {}, .key_path = {}, .scope = evaluation_scope::subcontext, .value = url}, cache,
        alloc, deadline);
    EXPECT_TRUE(output.is_map());
    EXPECT_EQ(attr, evaluation_scope::subcontext);

    EXPECT_JSON(output.ref(),
        R"({"scheme":"https","userinfo":"user","host":"test.com","port":222,"path":"/path","query":{"normal":"value","array":["1","2"],"emptyvalue":"","flag":true,"query":["value1","value2"]},"fragment":"frag"})");
}

TEST(TestUriParseProcessor, Malformed)
{
    auto *alloc = memory::get_default_resource();

    std::vector<std::string> samples = {"http://authority?que<>ry"};

    uri_parse_processor gen{"id", {}, {}, false, true};

    for (auto &url : samples) {
        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto [output, attr] = gen.eval_impl(
            {.address = {}, .key_path = {}, .scope = evaluation_scope::context, .value = url},
            cache, alloc, deadline);
        EXPECT_TRUE(output.is_invalid());
    }
}

} // namespace
