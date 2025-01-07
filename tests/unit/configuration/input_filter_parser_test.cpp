// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/exclusion_parser.hpp"
#include "parameter.hpp"

using namespace ddwaf;

namespace {

auto find_filter(const std::vector<input_filter_spec> &filters, std::string_view id)
{
    for (auto it = filters.begin(); it != filters.end(); ++it) {
        if (it->id == id) {
            return it;
        }
    }
    return filters.end();
}

TEST(TestInputFilterParser, ParseEmpty)
{
    object_limits limits;
    auto object = yaml_to_object(R"([{id: 1, inputs: []}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty exclusion filter");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestInputFilterParser, ParseFilterWithoutID)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{inputs: [{address: http.client_ip}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'id'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestInputFilterParser, ParseDuplicateFilters)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}]}, {id: 1, inputs: [{address: usr.id}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate filter");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);
}

TEST(TestInputFilterParser, ParseUnconditionalNoTargets)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, inputs: [{address: http.client_ip}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 0);
    EXPECT_TRUE(filter_it->filter);
}

TEST(TestInputFilterParser, ParseUnconditionalTargetID)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 1);
    EXPECT_TRUE(filter_it->filter);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestInputFilterParser, ParseUnconditionalTargetTags)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 1);
    EXPECT_TRUE(filter_it->filter);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::tags);
    EXPECT_TRUE(target.ref_id.empty());
    EXPECT_EQ(target.tags.size(), 2);
    EXPECT_STR(target.tags.find("type")->second, "rule");
    EXPECT_STR(target.tags.find("category")->second, "unknown");
}

TEST(TestInputFilterParser, ParseUnconditionalTargetPriority)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939, tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 1);
    EXPECT_TRUE(filter_it->filter);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestInputFilterParser, ParseUnconditionalMultipleTargets)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}, {tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 2);
    EXPECT_TRUE(filter_it->filter);

    {
        const auto &target = filter_it->targets[0];
        EXPECT_EQ(target.type, reference_type::id);
        EXPECT_STR(target.ref_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &target = filter_it->targets[1];
        EXPECT_EQ(target.type, reference_type::tags);
        EXPECT_TRUE(target.ref_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestInputFilterParser, ParseMultipleUnconditional)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}]}, {id: 2, inputs: [{address: usr.id}], rules_target: [{tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("2"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 2);

    {
        const auto &filter_it = find_filter(cfg.input_filters, "1");
        EXPECT_STR(filter_it->id, "1");

        EXPECT_EQ(filter_it->expr->size(), 0);
        EXPECT_EQ(filter_it->targets.size(), 1);
        EXPECT_TRUE(filter_it->filter);

        const auto &target = filter_it->targets[0];
        EXPECT_EQ(target.type, reference_type::id);
        EXPECT_STR(target.ref_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &filter_it = find_filter(cfg.input_filters, "2");
        EXPECT_STR(filter_it->id, "2");

        EXPECT_EQ(filter_it->expr->size(), 0);
        EXPECT_EQ(filter_it->targets.size(), 1);
        EXPECT_TRUE(filter_it->filter);

        const auto &target = filter_it->targets[0];
        EXPECT_EQ(target.type, reference_type::tags);
        EXPECT_TRUE(target.ref_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestInputFilterParser, ParseConditionalSingleCondition)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 1);
    EXPECT_EQ(filter_it->targets.size(), 1);
    EXPECT_TRUE(filter_it->filter);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestInputFilterParser, ParseConditionalMultipleConditions)
{
    object_limits limits;
    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);

    const auto &filter_it = cfg.input_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 3);
    EXPECT_EQ(filter_it->targets.size(), 1);
    EXPECT_TRUE(filter_it->filter);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestInputFilterParser, IncompatibleMinVersion)
{
    object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, inputs: [{address: http.client_ip}], min_version: 99.0.0}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_NE(skipped.find("1"), skipped.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestInputFilterParser, IncompatibleMaxVersion)
{
    object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, inputs: [{address: http.client_ip}], max_version: 0.0.99}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_NE(skipped.find("1"), skipped.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestInputFilterParser, CompatibleVersion)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, inputs: [{address: http.client_ip}], min_version: 0.0.99, max_version: 2.0.0}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 1);
}

} // namespace
