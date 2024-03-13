// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "test_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestParserV2Actions, ParseEmpty)
{
    auto object = yaml_to_object(R"([{id: block_1, type: block_request, parameters: {}}])");

    ddwaf::ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    auto actions = parser::v2::parse_actions(actions_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block_1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(actions->contains("block_1"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
}

} // namespace
