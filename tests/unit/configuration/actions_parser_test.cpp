// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/actions_parser.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "fmt/core.h"
#include "parameter.hpp"

using namespace ddwaf;

namespace {

const action_spec &find_action(const std::vector<action_spec> &actions, std::string_view id)
{
    for (const auto &action : actions) {
        if (action.id == id) {
            return action;
        }
    }
    throw;
}

bool contains_action(const std::vector<action_spec> &actions, std::string_view id)
{
    for (const auto &action : actions) {
        if (action.id == id) {
            return true;
        }
    }
    return false;
}

TEST(TestActionsParser, EmptyActions)
{
    auto object = yaml_to_object(R"([])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    EXPECT_EQ(cfg.actions.size(), 0);
}

TEST(TestActionsParser, SingleAction)
{
    auto object = yaml_to_object(R"([{id: block_1, type: block_request, parameters: {}}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block_1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "block_1"));
}

TEST(TestActionsParser, RedirectAction)
{
    std::vector<std::tuple<std::string, std::string, std::string>> redirections{
        {"redirect_301", "301", "http://www.datadoghq.com"},
        {"redirect_302", "302", "http://www.datadoghq.com"},
        {"redirect_303", "303", "http://www.datadoghq.com"},
        {"redirect_307", "307", "http://www.datadoghq.com"},
        {"redirect_https", "303", "https://www.datadoghq.com"},
        {"redirect_path", "303", "/security/appsec"},
    };

    std::string yaml;
    yaml.append("[");
    for (auto &[name, status_code, url] : redirections) {
        yaml += fmt::format("{{id: {}, parameters: {{location: \"{}\", status_code: {}}}, type: "
                            "redirect_request}},",
            name, url, status_code);
    }
    yaml.append("]");
    auto object = yaml_to_object(yaml);

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 6);
        EXPECT_NE(loaded.find("redirect_301"), loaded.end());
        EXPECT_NE(loaded.find("redirect_302"), loaded.end());
        EXPECT_NE(loaded.find("redirect_303"), loaded.end());
        EXPECT_NE(loaded.find("redirect_307"), loaded.end());
        EXPECT_NE(loaded.find("redirect_https"), loaded.end());
        EXPECT_NE(loaded.find("redirect_path"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 6);

    for (auto &[name, status_code, url] : redirections) {
        ASSERT_TRUE(contains_action(cfg.actions, name));

        const auto &spec = find_action(cfg.actions, name);
        EXPECT_EQ(spec.type, action_type::redirect_request) << name;
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), status_code.c_str());
        EXPECT_STR(parameters.at("location"), url.c_str());
    }
}

TEST(TestActionsParser, RedirectActionInvalidStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 404}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "redirect"));

    {
        const auto &spec = find_action(cfg.actions, "redirect");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "303");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestActionsParser, RedirectActionInvalid300StatusCode)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 304}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "redirect"));

    {
        const auto &spec = find_action(cfg.actions, "redirect");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "303");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestActionsParser, RedirectActionMissingStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {location: "http://www.google.com"}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "redirect"));

    {
        const auto &spec = find_action(cfg.actions, "redirect");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "303");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestActionsParser, RedirectActionMissingLocation)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {status_code: 303}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "redirect"));

    {
        const auto &spec = find_action(cfg.actions, "redirect");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, RedirectActionNonHttpURL)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {status_code: 303, location: ftp://myftp.mydomain.com}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "redirect"));

    {
        const auto &spec = find_action(cfg.actions, "redirect");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, RedirectActionInvalidRelativePathURL)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {status_code: 303, location: ../../../etc/passwd}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "redirect"));

    {
        const auto &spec = find_action(cfg.actions, "redirect");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, OverrideDefaultBlockAction)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {location: "http://www.google.com", status_code: 302}, type: redirect_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));

    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "block"));

    {
        const auto &spec = find_action(cfg.actions, "block");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "302");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestActionsParser, BlockActionMissingStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: 302}, type: block_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "block"));

    {
        const auto &spec = find_action(cfg.actions, "block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "302");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, UnknownActionType)
{
    auto object = yaml_to_object(
        R"([{id: sanitize, parameters: {location: "http://www.google.com", status_code: 302}, type: new_action_type}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("sanitize"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "sanitize"));
}

TEST(TestActionsParser, BlockActionMissingGrpcStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {type: "auto", status_code: 302}, type: block_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "block"));

    {
        const auto &spec = find_action(cfg.actions, "block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "302");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, BlockActionMissingType)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {grpc_status_code: 11, status_code: 302}, type: block_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "block"));

    {
        const auto &spec = find_action(cfg.actions, "block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "302");
        EXPECT_STR(parameters.at("grpc_status_code"), "11");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, BlockActionMissingParameters)
{
    auto object = yaml_to_object(R"([{id: block, parameters: {}, type: block_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(contains_action(cfg.actions, "block"));

    {
        const auto &spec = find_action(cfg.actions, "block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestActionsParser, MissingID)
{
    auto object = yaml_to_object(
        R"([{parameters: {location: "http://www.google.com", status_code: 302}, type: new_action_type}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    EXPECT_EQ(cfg.actions.size(), 0);

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
}

TEST(TestActionsParser, MissingType)
{
    auto object = yaml_to_object(
        R"([{id: sanitize, parameters: {location: "http://www.google.com", status_code: 302}}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    EXPECT_EQ(cfg.actions.size(), 0);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());

        ddwaf_object_free(&root);
    }
}

TEST(TestActionsParser, MissingParameters)
{
    auto object = yaml_to_object(R"([{id: sanitize, type: sanitize_request}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_actions(actions_array, cfg, ids, section));
    ddwaf_object_free(&object);

    EXPECT_EQ(cfg.actions.size(), 0);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());

        ddwaf_object_free(&root);
    }
}

} // namespace
