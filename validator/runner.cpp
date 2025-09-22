// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.

#include "runner.hpp"
#include "assert.hpp"
#include "ddwaf.h"
#include "utils.hpp"

test_runner::test_runner(const std::string &rule_file)
{
    YAML::Node doc = YAML::Load(read_file(rule_file));
    auto rule_obj = doc.as<ddwaf_object>();
    handle_ = ddwaf_init(&rule_obj, nullptr, nullptr);
    ddwaf_object_destroy(&rule_obj, ddwaf_get_default_allocator());
    if (handle_ == nullptr) {
        throw std::runtime_error("Invalid rule file");
    }

    auto rules_node = doc["rules"];
    for (auto it = rules_node.begin(); it != rules_node.end(); ++it) {
        YAML::Node rule_node = *it;
        auto id = rule_node["id"].as<std::string>();
        rules_[id] = rule_node;
    }

    auto custom_rules_node = doc["custom_rules"];
    for (auto it = custom_rules_node.begin(); it != custom_rules_node.end(); ++it) {
        YAML::Node rule_node = *it;
        auto id = rule_node["id"].as<std::string>();
        custom_rules_[id] = rule_node;
    }
}

test_runner::~test_runner() { ddwaf_destroy(handle_); }

bool test_runner::run_self_test(const YAML::Node &runs)
{
    bool passed = false;

    try {
        expect(true, runs.IsDefined());
        expect(true, runs.size() > 0);
        for (auto it = runs.begin(); it != runs.end(); ++it) {
            YAML::Node run = *it;
            validate(run["rules"], run["output"]);
        }
        passed = true;
    } catch (const std::exception &e) {
        error_ << e.what();
    } catch (...) {
        error_ << "unknown exception";
    }

    return passed;
}

bool test_runner::run_test(const YAML::Node &runs)
{
    auto *alloc = ddwaf_get_default_allocator();

    bool passed = false;
    std::unique_ptr<std::remove_pointer_t<ddwaf_context>, decltype(&ddwaf_context_destroy)> ctx(
        ddwaf_context_init(handle_, alloc), ddwaf_context_destroy);

    ddwaf_object res_mem{};
    ddwaf_object_set_invalid(&res_mem);

    auto destroy_fn = [alloc](ddwaf_object *ptr) { ddwaf_object_destroy(ptr, alloc); };
    std::unique_ptr<ddwaf_object, decltype(destroy_fn)> res{&res_mem, destroy_fn};

    try {
        expect(true, runs.IsDefined());
        expect(true, runs.size() > 0);
        for (auto it = runs.begin(); it != runs.end(); ++it) {
            if (it->IsMap()) { // context
                YAML::Node run = *it;
                DDWAF_RET_CODE code = DDWAF_OK;
                if (run["code"].as<std::string>() == "match") {
                    code = DDWAF_MATCH;
                }

                ddwaf_object *data_ptr = nullptr;
                auto data = run["input"].as<ddwaf_object>();
                if (ddwaf_object_get_type(&data) != DDWAF_OBJ_INVALID) {
                    data_ptr = &data;
                }

                auto retval = ddwaf_context_eval(ctx.get(), data_ptr, alloc, res.get(), timeout);

                expect(retval, code);

                auto res_yaml = object_to_yaml(*res);
                validate(run["rules"], res_yaml["events"]);
                validate_actions(run["actions"], res_yaml["actions"]);
                validate_attributes(run["attributes"], res_yaml["attributes"]);

                ddwaf_object_destroy(res.get(), alloc);
            } else { // subcontext sequence
                YAML::Node sub_runs = *it;
                expect(true, sub_runs.size() > 0);

                std::unique_ptr<std::remove_pointer_t<ddwaf_subcontext>,
                    decltype(&ddwaf_subcontext_destroy)>
                    sctx(ddwaf_subcontext_init(ctx.get()), ddwaf_subcontext_destroy);

                for (auto sub_it = sub_runs.begin(); sub_it != sub_runs.end(); ++sub_it) {
                    YAML::Node run = *sub_it;

                    DDWAF_RET_CODE code = DDWAF_OK;
                    if (run["code"].as<std::string>() == "match") {
                        code = DDWAF_MATCH;
                    }

                    ddwaf_object *data_ptr = nullptr;
                    auto data = run["input"].as<ddwaf_object>();
                    if (ddwaf_object_get_type(&data) != DDWAF_OBJ_INVALID) {
                        data_ptr = &data;
                    }

                    auto retval =
                        ddwaf_subcontext_eval(sctx.get(), data_ptr, alloc, res.get(), timeout);

                    expect(retval, code);
                    if (code == DDWAF_MATCH) {
                        auto res_yaml = object_to_yaml(*res);
                        validate(run["rules"], res_yaml["events"]);
                        validate_actions(run["actions"], res_yaml["actions"]);
                        validate_attributes(run["attributes"], res_yaml["attributes"]);
                    }

                    ddwaf_object_destroy(res.get(), alloc);
                }
            }
        }
        passed = true;
    } catch (const std::exception &e) {
        error_ << e.what();
    } catch (...) {
        error_ << "unknown exception";
    }

    if (!passed) {
        YAML::Emitter out(output_);
        out.SetIndent(2);
        out.SetMapFormat(YAML::Block);
        out.SetSeqFormat(YAML::Block);
        out << object_to_yaml(*res);
    }

    return passed;
}

test_runner::result test_runner::run(const fs::path &file)
{
    output_ = {};
    error_ = {};

    bool passed = false;
    bool expected_fail = false;

    try {
        YAML::Node sample = YAML::Load(read_file(file.c_str()));

        if (sample["expected-fail"].IsDefined()) {
            expected_fail = sample["expected-fail"].as<bool>();
        }

        if (sample["self-test"].IsDefined() && sample["self-test"].as<bool>()) {
            passed = run_self_test(sample["runs"]);
        } else {
            passed = run_test(sample["runs"]);
        }
    } catch (const std::exception &e) {
        error_ << e.what();
    } catch (...) {
        error_ << "unknown exception";
    }

    return {passed, expected_fail, error_.str(), output_.str()};
}

void test_runner::validate(const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected.size(), obtained.size());

    std::vector<bool> seen(obtained.size(), false);

    bool found_expected = false;
    for (const auto &expected_rule_matches : expected) {
        for (std::size_t j = 0; j < obtained.size(); j++) {
            auto obtained_rule_match = obtained[j];
            auto id = obtained_rule_match["rule"]["id"].as<std::string>();

            auto expected_rule_match = expected_rule_matches[id];
            if (!expected_rule_match.IsDefined()) {
                continue;
            }

            expect(false, static_cast<bool>(seen[j]));

            seen[j] = true;
            found_expected = true;

            YAML::Node rule;
            if (rules_.contains(id)) {
                rule = rules_[id];
            } else {
                rule = custom_rules_[id];
            }

            validate_rule(rule, obtained_rule_match["rule"]);
            validate_conditions(rule["conditions"], obtained_rule_match["rule_matches"]);
            validate_matches(expected_rule_match, obtained_rule_match["rule_matches"]);
        }

        expect(true, found_expected);
    }

    for (bool v : seen) { expect(true, v); }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void test_runner::validate_rule(const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected["id"], obtained["id"]);
    expect(expected["name"], obtained["name"]);

    auto expected_tags = expected["tags"];
    auto obtained_tags = obtained["tags"];

    expect(expected_tags["type"], obtained_tags["type"]);
    expect(expected_tags["category"], obtained_tags["category"]);

    auto expected_actions = expected["on_match"];
    auto obtained_actions = obtained["on_match"];
    if (expected_actions.IsDefined()) {
        expect(true, obtained_actions.IsDefined());

        if (obtained_actions.size() == 1 && obtained_actions[0].as<std::string>() == "monitor") {
            return;
        }
        expect(expected_actions.size(), obtained_actions.size());

        expect(expected_actions, obtained_actions);
    }
}

void test_runner::validate_conditions(const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected.size(), obtained.size());

    // Iterate through matches, assume they are in the same order as rule
    // conditions for now.
    for (std::size_t i = 0; i < expected.size(); i++) {
        auto expected_cond = expected[i];
        auto obtained_cond = obtained[i];

        // Remove the version of the operator as it is not reported within events
        auto expected_operator = expected_cond["operator"].as<std::string>();
        auto version_idx = expected_operator.find("@v");
        if (version_idx != std::string::npos) {
            expected_operator = expected_operator.substr(0, version_idx);
        }

        expect(expected_operator, obtained_cond["operator"].as<std::string>());

        auto op = expected_cond["operator"].as<std::string>();
        if (op == "match_regex") {
            expect(expected_cond["parameters"]["regex"].as<std::string>(),
                obtained_cond["operator_value"].as<std::string>());
        }
    }
}

void test_runner::validate_matches(const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected.size(), obtained.size());

    static std::set<std::string_view, std::less<>> scalar_operators{"match_regex", "phrase_match",
        "exact_match", "ip_match", "equals", "is_sqli", "is_xss", "exists", "greater_than",
        "lower_than", "!match_regex", "!phrase_match", "!exact_match", "!ip_match", "!equals",
        "!is_sqli", "!is_xss", "!exists"};

    // Iterate through matches, assume they are in the same order as rule
    // conditions for now.
    for (std::size_t i = 0; i < expected.size(); i++) {
        auto expected_match = expected[i];
        auto obtained_match = obtained[i]["parameters"][0];

        auto op = obtained[i]["operator"].as<std::string>();
        if (scalar_operators.contains(op)) {
            if (expected_match["address"].IsDefined()) {
                expect(expected_match["address"], obtained_match["address"]);
            }
            if (expected_match["key_path"].IsDefined()) {
                expect(expected_match["key_path"], obtained_match["key_path"]);
            }
            if (expected_match["value"].IsDefined()) {
                expect(expected_match["value"], obtained_match["value"]);
            }
        } else {
            for (YAML::const_iterator it = expected_match.begin(); it != expected_match.end();
                 ++it) {
                auto key = it->first.as<std::string>();
                auto expected_param = it->second;
                auto obtained_param = obtained_match[key];

                if (expected_param.IsMap()) {
                    if (expected_param["address"].IsDefined()) {
                        expect(expected_param["address"], obtained_param["address"]);
                    }
                    if (expected_param["key_path"].IsDefined()) {
                        expect(expected_param["key_path"], obtained_param["key_path"]);
                    }
                    if (expected_param["value"].IsDefined()) {
                        expect(expected_param["value"], obtained_param["value"]);
                    }
                }
            }
        }
    }
}

void test_runner::validate_actions(const YAML::Node &expected, const YAML::Node &obtained)
{
    if (!expected.IsDefined()) {
        return;
    }

    expect(expected.size(), obtained.size());
    for (YAML::const_iterator it = expected.begin(); it != expected.end(); ++it) {
        auto key = it->first.as<std::string>();
        auto expected_action = it->second;
        auto obtained_action = obtained[key];

        validate_action_params(expected_action, obtained_action);
    }
}

void test_runner::validate_action_params(const YAML::Node &expected, const YAML::Node &obtained)
{
    if (!expected.IsDefined()) {
        return;
    }

    validate_equals(expected, obtained);
}

void test_runner::validate_attributes(const YAML::Node &expected, const YAML::Node &obtained)
{
    if (!expected.IsDefined()) {
        return;
    }

    validate_equals(expected, obtained);
}

// NOLINTNEXTLINE(misc-no-recursion)
void test_runner::validate_equals(const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(true, obtained.IsDefined());
    expect(expected.Type(), obtained.Type());

    switch (expected.Type()) {
    case YAML::NodeType::Map: {
        expect(expected.size(), obtained.size());

        for (auto it = expected.begin(); it != expected.end(); ++it) {
            validate_equals(it->second, obtained[it->first.as<std::string>()]);
        }
        break;
    }
    case YAML::NodeType::Sequence: {
        expect(expected.size(), obtained.size());

        std::vector<bool> seen(expected.size(), false);
        for (unsigned i = 0; i < expected.size(); ++i) {
            bool found = false;
            for (unsigned j = 0; j < obtained.size(); ++j) {
                try {
                    if (!seen[j]) {
                        validate_equals(expected[i], obtained[j]);
                        seen[j] = found = true;
                        break;
                    }
                } catch (...) {}
            }
            expect(true, found);
        }
        break;
    }
    case YAML::NodeType::Scalar:
        expect(expected.as<std::string>(), obtained.as<std::string>());
        break;
    default:
        break;
    }
}
