// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/actions_parser.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "fmt/core.h"

using namespace ddwaf;

namespace {

TEST(TestActionParser, EmptyActions)
{
    auto object = yaml_to_object<owned_object>(R"([])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
}

TEST(TestActionParser, SingleAction)
{
    auto object =
        yaml_to_object<owned_object>(R"([{id: block_1, type: block_request, parameters: {}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block_1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(cfg.actions.size(), 1);
    EXPECT_TRUE(cfg.actions.contains("block_1"));

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_TRUE(change.actions.contains("block_1"));

    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());

    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
}

TEST(TestActionParser, RedirectAction)
{
    std::vector<std::tuple<std::string, uint64_t, std::string>> redirections{
        {"redirect_301", 301, "http://www.datadoghq.com"},
        {"redirect_302", 302, "http://www.datadoghq.com"},
        {"redirect_303", 303, "http://www.datadoghq.com"},
        {"redirect_307", 307, "http://www.datadoghq.com"},
        {"redirect_https", 303, "https://www.datadoghq.com"},
        {"redirect_path", 303, "/security/appsec"},
    };

    std::string yaml;
    yaml.append("[");
    for (auto &[name, status_code, url] : redirections) {
        yaml += fmt::format("{{id: {}, parameters: {{location: \"{}\", status_code: {}}}, type: "
                            "redirect_request}},",
            name, url, status_code);
    }
    yaml.append("]");
    auto object = yaml_to_object<owned_object>(yaml);

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 6);
        EXPECT_NE(loaded.find("redirect_301"), loaded.end());
        EXPECT_NE(loaded.find("redirect_302"), loaded.end());
        EXPECT_NE(loaded.find("redirect_303"), loaded.end());
        EXPECT_NE(loaded.find("redirect_307"), loaded.end());
        EXPECT_NE(loaded.find("redirect_https"), loaded.end());
        EXPECT_NE(loaded.find("redirect_path"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 6);
    EXPECT_EQ(cfg.actions.size(), 6);

    for (auto &[name, status_code, url] : redirections) {
        EXPECT_TRUE(change.actions.contains(name));
        ASSERT_TRUE(cfg.actions.contains(name));

        const auto &spec = cfg.actions[name];
        EXPECT_EQ(spec.type, action_type::redirect_request) << name;
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), status_code);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), url);
    }

    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());

    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
}

TEST(TestActionParser, RedirectActionInvalidStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 404}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionNegativeStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: -303}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionStatusCodeOutOfRange)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 1000}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionInvalid300StatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 304}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionStringStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: "303"}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionValidFloatStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 307.0}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 307);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionInvalidFloatStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com", status_code: 303.33}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionMissingStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {location: "http://www.google.com"}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 303);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, RedirectActionMissingLocation)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {status_code: 303}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, RedirectActionNonHttpURL)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {status_code: 303, location: ftp://myftp.mydomain.com}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, RedirectActionInvalidRelativePathURL)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: redirect, parameters: {status_code: 303, location: ../../../etc/passwd}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("redirect"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("redirect"));
    EXPECT_TRUE(cfg.actions.contains("redirect"));

    {
        const auto &spec = cfg.actions["redirect"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, OverrideDefaultBlockAction)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {location: "http://www.google.com", status_code: 302}, type: redirect_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::redirect_request);
        EXPECT_EQ(spec.type_str, "redirect_request");
        EXPECT_EQ(spec.parameters.size(), 2);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 302);
        EXPECT_STR(std::get<std::string>(parameters.at("location")), "http://www.google.com");
    }
}

TEST(TestActionParser, BlockActionMissingStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: 302}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 302);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionNegativeStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: -302, status_code: -10}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionStringStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: "302", status_code: "10"}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 10);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 302);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionInvalidFloatStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: 302.33, status_code: 110.33}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionValidFloatStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: 302.0, status_code: 110.0}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 110);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 302);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionStatusCodeOutOfRange)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", grpc_status_code: 1000, status_code: 1000}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, UnknownActionType)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: sanitize, parameters: {location: "http://www.google.com", status_code: 302}, type: new_action_type}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("sanitize"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("sanitize"));
    EXPECT_TRUE(cfg.actions.contains("sanitize"));
}

TEST(TestActionParser, BlockActionMissingGrpcStatusCode)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {type: "auto", status_code: 302}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 302);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionMissingType)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block, parameters: {grpc_status_code: 11, status_code: 302}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 302);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 11);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, BlockActionMissingParameters)
{
    auto object =
        yaml_to_object<owned_object>(R"([{id: block, parameters: {}, type: block_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block"));
    EXPECT_TRUE(cfg.actions.contains("block"));

    {
        const auto &spec = cfg.actions["block"];
        EXPECT_EQ(spec.type, action_type::block_request);
        EXPECT_EQ(spec.type_str, "block_request");
        EXPECT_EQ(spec.parameters.size(), 3);

        const auto &parameters = spec.parameters;
        EXPECT_EQ(std::get<uint64_t>(parameters.at("status_code")), 403);
        EXPECT_EQ(std::get<uint64_t>(parameters.at("grpc_status_code")), 10);
        EXPECT_STR(std::get<std::string>(parameters.at("type")), "auto");
    }
}

TEST(TestActionParser, MissingID)
{
    auto object = yaml_to_object<owned_object>(
        R"([{parameters: {location: "http://www.google.com", status_code: 302}, type: new_action_type}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    EXPECT_EQ(change.actions.size(), 0);
    EXPECT_EQ(cfg.actions.size(), 0);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'id'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());
    }
}

TEST(TestActionParser, MissingType)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: sanitize, parameters: {location: "http://www.google.com", status_code: 302}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    EXPECT_EQ(change.actions.size(), 0);
    EXPECT_EQ(cfg.actions.size(), 0);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());
    }
}

TEST(TestActionParser, MissingParameters)
{
    auto object = yaml_to_object<owned_object>(R"([{id: sanitize, type: sanitize_request}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    EXPECT_EQ(change.actions.size(), 0);
    EXPECT_EQ(cfg.actions.size(), 0);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());
    }
}

TEST(TestActionParser, DuplicateAction)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: block_1, type: block_request, parameters: {}},{id: block_1, type: block_request, parameters: {}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("block_1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("duplicate action");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("block_1"), error_rules.end());
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("block_1"));
    EXPECT_TRUE(cfg.actions.contains("block_1"));
}

TEST(TestActionParser, ParameterTypes)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: sanitize, parameters: {string: thisisastring, int64: -200, uint64: 18446744073709551615, double: 22.22, bool: true}, type: new_action_type}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("sanitize"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::actions);
    EXPECT_EQ(change.actions.size(), 1);
    EXPECT_EQ(cfg.actions.size(), 1);

    EXPECT_TRUE(change.actions.contains("sanitize"));
    EXPECT_TRUE(cfg.actions.contains("sanitize"));

    auto &spec = cfg.actions.find("sanitize")->second;

    auto it = spec.parameters.find("string");
    EXPECT_NE(it, spec.parameters.end());
    ASSERT_TRUE(std::holds_alternative<std::string>(it->second));
    EXPECT_STR(std::get<std::string>(it->second), "thisisastring");

    it = spec.parameters.find("int64");
    EXPECT_NE(it, spec.parameters.end());
    EXPECT_TRUE(std::holds_alternative<int64_t>(it->second));
    EXPECT_EQ(std::get<int64_t>(it->second), -200);

    it = spec.parameters.find("uint64");
    EXPECT_NE(it, spec.parameters.end());
    EXPECT_TRUE(std::holds_alternative<uint64_t>(it->second));
    EXPECT_EQ(std::get<uint64_t>(it->second), std::numeric_limits<uint64_t>::max());

    it = spec.parameters.find("double");
    EXPECT_NE(it, spec.parameters.end());
    EXPECT_TRUE(std::holds_alternative<double>(it->second));
    EXPECT_EQ(std::get<double>(it->second), 22.22);

    it = spec.parameters.find("bool");
    EXPECT_NE(it, spec.parameters.end());
    EXPECT_TRUE(std::holds_alternative<bool>(it->second));
    EXPECT_EQ(std::get<bool>(it->second), true);
}

TEST(TestActionParser, InvalidParameterContainer)
{
    auto object =
        yaml_to_object<owned_object>(R"([{id: sanitize, parameters: [], type: new_action_type}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("invalid type 'array' for key 'parameters', expected 'map'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());
    }
}

TEST(TestActionParser, InvalidParameterType)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: sanitize, parameters: {value: {}}, type: new_action_type}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto actions_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_actions(actions_array, collector, section);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("sanitize"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("malformed object, item in scalar map not a valid scalar");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("sanitize"), error_rules.end());
    }
}

} // namespace
