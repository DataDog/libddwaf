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

TEST(TestParserV2Scanner, ParseKeyOnlyScanner)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 1);
    EXPECT_NE(scanners.find_by_id("ecd"), nullptr);

    auto *scnr = scanners.find_by_id("ecd");
    ;
    EXPECT_STREQ(scnr->get_id().data(), "ecd");
    boost::unordered_flat_map<std::string, std::string> tags{
        {"type", "email"}, {"category", "pii"}};
    EXPECT_EQ(scnr->get_tags(), tags);

    ddwaf_object value;
    ddwaf_object_string(&value, "dog@datadoghq.com");
    EXPECT_TRUE(scnr->eval("email", value));
    EXPECT_FALSE(scnr->eval("mail", value));
    ddwaf_object_free(&value);

    ddwaf_object_string(&value, "ansodinsod");
    EXPECT_TRUE(scnr->eval("email", value));
    ddwaf_object_free(&value);
}

TEST(TestParserV2Scanner, ParseValueOnlyScanner)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","value":{"operator":"match_regex","parameters":{"regex":"@"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 1);
    EXPECT_NE(scanners.find_by_id("ecd"), nullptr);

    auto *scnr = scanners.find_by_id("ecd");
    ;
    EXPECT_STREQ(scnr->get_id().data(), "ecd");
    boost::unordered_flat_map<std::string, std::string> tags{
        {"type", "email"}, {"category", "pii"}};
    EXPECT_EQ(scnr->get_tags(), tags);

    ddwaf_object value;
    ddwaf_object_string(&value, "dog@datadoghq.com");
    EXPECT_TRUE(scnr->eval("email", value));
    EXPECT_TRUE(scnr->eval("mail", value));
    ddwaf_object_free(&value);

    ddwaf_object_string(&value, "ansodinsod");
    EXPECT_FALSE(scnr->eval("email", value));
    ddwaf_object_free(&value);
}

TEST(TestParserV2Scanner, ParseKeyValueScanner)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"@"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 1);
    EXPECT_NE(scanners.find_by_id("ecd"), nullptr);

    auto *scnr = scanners.find_by_id("ecd");
    ;
    EXPECT_STREQ(scnr->get_id().data(), "ecd");
    boost::unordered_flat_map<std::string, std::string> tags{
        {"type", "email"}, {"category", "pii"}};
    EXPECT_EQ(scnr->get_tags(), tags);

    ddwaf_object value;
    ddwaf_object_string(&value, "dog@datadoghq.com");
    EXPECT_TRUE(scnr->eval("email", value));
    EXPECT_FALSE(scnr->eval("mail", value));
    ddwaf_object_free(&value);

    ddwaf_object_string(&value, "ansodinsod");
    EXPECT_FALSE(scnr->eval("email", value));
    ddwaf_object_free(&value);
}

TEST(TestParserV2Scanner, ParseNoID)
{
    auto definition = json_to_object(
        R"([{"key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"@"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'id'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseNoTags)
{
    auto definition = json_to_object(
        R"([{"id":"error","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"@"}}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'tags'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseNoKeyValue)
{
    auto definition =
        json_to_object(R"([{"id":"error","tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("scanner has no key or value matcher");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseDuplicate)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}},{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate scanner");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 1);
}

TEST(TestParserV2Scanner, ParseKeyNoOperator)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'operator'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseKeyNoParameters)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex"},"value":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseValueNoOperator)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'operator'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseValueNoParameters)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex"},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseUnknownMatcher)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"what","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("unknown matcher: what");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}

TEST(TestParserV2Scanner, ParseRuleDataID)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"exact_match","parameters":{"data":"invalid"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<parameter::vector>(parameter(definition));

    ddwaf::ruleset_info::section_info section;
    auto scanners = parser::v2::parse_scanners(scanners_array, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("dynamic data on scanner condition");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(scanners.size(), 0);
}
} // namespace
