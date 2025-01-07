// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/rule_parser.hpp"
#include "parameter.hpp"

using namespace ddwaf;

namespace {

const rule_spec &find_rule(const std::vector<rule_spec> &rules, std::string_view id)
{
    for (const auto &rule : rules) {
        if (rule.id == id) {
            return rule;
        }
    }
    throw;
}

bool contains_rule(const std::vector<rule_spec> &rules, std::string_view id)
{
    for (const auto &rule : rules) {
        if (rule.id == id) {
            return true;
        }
    }
    return false;
}

TEST(TestBaseRuleParser, ParseRule)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    ASSERT_TRUE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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

    EXPECT_EQ(cfg.base_rules.size(), 1);
    EXPECT_TRUE(contains_rule(cfg.base_rules, "1"));

    const rule_spec &rule = find_rule(cfg.base_rules, "1");
    EXPECT_TRUE(rule.enabled);
    EXPECT_EQ(rule.expr->size(), 3);
    EXPECT_EQ(rule.actions.size(), 0);
    EXPECT_STR(rule.name, "rule1");
    EXPECT_EQ(rule.tags.size(), 2);
    EXPECT_STR(rule.tags.at("type"), "flow1");
    EXPECT_STR(rule.tags.at("category"), "category1");
}

TEST(TestBaseRuleParser, ParseRuleWithoutType)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, ParseRuleInvalidTransformer)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y], transformers: [unknown]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("invalid transformer unknown");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}
TEST(TestBaseRuleParser, ParseRuleWithoutID)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{name: rule1, tags: {type: type1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, ParseMultipleRules)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 2);

    ASSERT_TRUE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("secondrule"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 2);
    EXPECT_TRUE(contains_rule(cfg.base_rules, "1"));
    EXPECT_TRUE(contains_rule(cfg.base_rules, "secondrule"));

    {
        const rule_spec &rule = find_rule(cfg.base_rules, "1");
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags.at("type"), "flow1");
        EXPECT_STR(rule.tags.at("category"), "category1");
    }

    {
        const rule_spec &rule = find_rule(cfg.base_rules, "secondrule");
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags.at("type"), "flow2");
        EXPECT_STR(rule.tags.at("category"), "category2");
        EXPECT_STR(rule.tags.at("confidence"), "none");
    }
}

TEST(TestBaseRuleParser, ParseMultipleRulesOneInvalid)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}, {id: error}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));

    ASSERT_TRUE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("secondrule"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'conditions'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 2);
    EXPECT_TRUE(contains_rule(cfg.base_rules, "1"));
    EXPECT_TRUE(contains_rule(cfg.base_rules, "secondrule"));

    {
        const rule_spec &rule = find_rule(cfg.base_rules, "1");
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags.at("type"), "flow1");
        EXPECT_STR(rule.tags.at("category"), "category1");
    }

    {
        const rule_spec &rule = find_rule(cfg.base_rules, "secondrule");
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags.at("type"), "flow2");
        EXPECT_STR(rule.tags.at("category"), "category2");
        EXPECT_STR(rule.tags.at("confidence"), "none");
    }
}

TEST(TestBaseRuleParser, ParseMultipleRulesOneDuplicate)
{
    object_limits limits;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: 1, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 2);

    ASSERT_TRUE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("duplicate rule");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 1);
    EXPECT_TRUE(contains_rule(cfg.base_rules, "1"));

    {
        const rule_spec &rule = find_rule(cfg.base_rules, "1");
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags.at("type"), "flow1");
        EXPECT_STR(rule.tags.at("category"), "category1");
    }
}

TEST(TestBaseRuleParser, KeyPathTooLong)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x, y, z]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("key_path beyond maximum container depth");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, NegatedMatcherTooManyParameters)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: "!match_regex", parameters: {inputs: [{address: arg1}, {address: arg2}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("multiple targets for non-variadic argument");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, SupportedVersionedOperator)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{"id":"rsp-930-003","name":"SQLi Exploit detection","tags":{"type":"sqli","category":"exploit_detection","module":"rasp"},"conditions":[{"parameters":{"resource":[{"address":"server.db.statement"}],"params":[{"address":"server.request.query"},{"address":"server.request.body"},{"address":"server.request.path_params"},{"address":"grpc.server.request.message"},{"address":"graphql.server.all_resolvers"},{"address":"graphql.server.resolver"}],"db_type":[{"address":"server.db.system"}]},"operator":"sqli_detector@v2"}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_TRUE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rsp-930-003"));

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 1);
}

TEST(TestBaseRuleParser, UnsupportedVersionedOperator)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{"id":"rsp-930-003","name":"SQLi Exploit detection","tags":{"type":"sqli","category":"exploit_detection","module":"rasp"},"conditions":[{"parameters":{"resource":[{"address":"server.db.statement"}],"params":[{"address":"server.request.query"},{"address":"server.request.body"},{"address":"server.request.path_params"},{"address":"grpc.server.request.message"},{"address":"graphql.server.all_resolvers"},{"address":"graphql.server.resolver"}],"db_type":[{"address":"server.db.system"}]},"operator":"sqli_detector@v20"}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        EXPECT_TRUE(skipped.contains("rsp-930-003"));

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, IncompatibleMinVersion)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, min_version: 99.0.0, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        EXPECT_TRUE(skipped.contains("1"));

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, IncompatibleMaxVersion)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, max_version: 0.0.99, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_FALSE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

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
        EXPECT_TRUE(skipped.contains("1"));

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 0);
}

TEST(TestBaseRuleParser, CompatibleVersion)
{
    object_limits limits;
    limits.max_container_depth = 2;
    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, min_version: 0.0.99, max_version: 2.0.0, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    ASSERT_TRUE(parse_base_rules(rule_array, cfg, ids, section, limits));
    ;
    ddwaf_object_free(&rule_object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("1"));

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.base_rules.size(), 1);
}

} // namespace
