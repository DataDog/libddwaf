// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "fmt/core.h"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "test_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestParserV2Actions, EmptyActions)
{
    auto object = yaml_to_object(R"([])");

    ddwaf::ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    auto actions = parser::v2::parse_actions(actions_array, section);
    ddwaf_object_free(&object);

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));

    {
        const auto &spec = actions->at("block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }

    {
        const auto &spec = actions->at("stack_trace");
        EXPECT_EQ(spec.type, action_type::generate_stack);
        EXPECT_EQ(spec.type_str, "generate_stack");
        EXPECT_EQ(spec.parameters.size(), 0);
    }

    {
        const auto &spec = actions->at("extract_schema");
        EXPECT_EQ(spec.type, action_type::generate_schema);
        EXPECT_EQ(spec.type_str, "generate_schema");
        EXPECT_EQ(spec.parameters.size(), 0);
    }
}

TEST(TestParserV2Actions, SingleAction)
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

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("block_1"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
}

TEST(TestParserV2Actions, RedirectAction)
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

    ddwaf::ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    auto actions = parser::v2::parse_actions(actions_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 6);
        EXPECT_NE(loaded.find("redirect_301"), loaded.end());
        EXPECT_NE(loaded.find("redirect_302"), loaded.end());
        EXPECT_NE(loaded.find("redirect_303"), loaded.end());
        EXPECT_NE(loaded.find("redirect_307"), loaded.end());
        EXPECT_NE(loaded.find("redirect_https"), loaded.end());
        EXPECT_NE(loaded.find("redirect_path"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 10);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    for (auto &[name, status_code, url] : redirections) {
        ASSERT_TRUE(actions->contains(name));

        const auto &spec = actions->at(name);
        EXPECT_EQ(spec.type, action_type::redirect_request) << name;
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), status_code.c_str());
        EXPECT_STR(parameters.at("location"), url.c_str());
    }
}

TEST(TestParserV2Actions, RedirectActionInvalidStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 404}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("redirect"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("redirect");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "303");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestParserV2Actions, RedirectActionInvalid300StatusCode)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 304}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("redirect"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("redirect");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "303");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestParserV2Actions, RedirectActionMissingStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {location: "http://www.google.com"}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("redirect"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("redirect");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "303");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestParserV2Actions, RedirectActionMissingLocation)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {status_code: 303}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("redirect"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("redirect");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, RedirectActionNonHttpURL)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {status_code: 303, location: ftp://myftp.mydomain.com}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("redirect"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("redirect");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, RedirectActionInvalidRelativePathURL)
{
    auto object = yaml_to_object(
        R"([{id: redirect, parameters: {status_code: 303, location: ../../../etc/passwd}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("redirect"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("redirect");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, OverrideDefaultBlockAction)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {location: "http://www.google.com", status_code: 302}, type: redirect_request}])");

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
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("block");
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "302");
        EXPECT_STR(parameters.at("location"), "http://www.google.com");
    }
}

TEST(TestParserV2Actions, BlockActionMissingStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: 302}, type: block_request}])");

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
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "302");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, UnknownActionType)
{
    auto object = yaml_to_object(
        R"([{id: sanitize, parameters: {location: "http://www.google.com", status_code: 302}, type: new_action_type}])");

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
        EXPECT_NE(loaded.find("sanitize"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 5);
    EXPECT_TRUE(actions->contains("sanitize"));
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));
}

TEST(TestParserV2Actions, BlockActionMissingGrpcStatusCode)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {type: "auto", status_code: 302}, type: block_request}])");

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
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "302");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, BlockActionMissingType)
{
    auto object = yaml_to_object(
        R"([{id: block, parameters: {grpc_status_code: 11, status_code: 302}, type: block_request}])");

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
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "302");
        EXPECT_STR(parameters.at("grpc_status_code"), "11");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, BlockActionMissingParameters)
{
    auto object = yaml_to_object(R"([{id: block, parameters: {}, type: block_request}])");

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
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));

    {
        const auto &spec = actions->at("block");
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_STR(parameters.at("status_code"), "403");
        EXPECT_STR(parameters.at("grpc_status_code"), "10");
        EXPECT_STR(parameters.at("type"), "auto");
    }
}

TEST(TestParserV2Actions, MissingID)
{
    auto object = yaml_to_object(
        R"([{parameters: {location: "http://www.google.com", status_code: 302}, type: new_action_type}])");

    ddwaf::ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    auto actions = parser::v2::parse_actions(actions_array, section);
    ddwaf_object_free(&object);

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

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));
}

TEST(TestParserV2Actions, MissingType)
{
    auto object = yaml_to_object(
        R"([{id: sanitize, parameters: {location: "http://www.google.com", status_code: 302}}])");

    ddwaf::ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    auto actions = parser::v2::parse_actions(actions_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));
}

TEST(TestParserV2Actions, MissingParameters)
{
    auto object = yaml_to_object(R"([{id: sanitize, type: sanitize_request}])");

    ddwaf::ruleset_info::section_info section;
    auto actions_array = static_cast<parameter::vector>(parameter(object));
    auto actions = parser::v2::parse_actions(actions_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(actions->size(), 4);
    EXPECT_TRUE(actions->contains("block"));
    EXPECT_TRUE(actions->contains("stack_trace"));
    EXPECT_TRUE(actions->contains("extract_schema"));
    EXPECT_TRUE(actions->contains("monitor"));
}

} // namespace
