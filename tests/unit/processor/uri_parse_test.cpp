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

TEST(TestUriParseProcessor, Basic)
{
    std::string_view url =
        "https://user@test.com:222/"
        "path?query=value1&query=value2&flag&emptyvalue=&array[]=1&array[]=2&normal=value#frag";

    uri_parse_processor gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl(
        {.address = {}, .key_path = {}, .ephemeral = false, .value = url}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"scheme":"https","userinfo":"user","host":"test.com","port":222,"path":"/path","query":{"normal":"value","array":["1","2"],"emptyvalue":"","flag":true,"query":["value1","value2"]},"fragment":"frag"})");

    ddwaf_object_free(&output);
}

} // namespace
