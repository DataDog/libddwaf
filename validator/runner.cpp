// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.

#include "runner.hpp"
#include "assert.hpp"
#include "utils.hpp"

test_runner::test_runner(const std::string &rule_file)
{
    YAML::Node doc = YAML::Load(read_file(rule_file));
    auto rule_obj = doc.as<ddwaf_object>();
    handle_ = ddwaf_init(&rule_obj, nullptr, nullptr);
    ddwaf_object_free(&rule_obj);
    if (handle_ == nullptr) {
        throw std::runtime_error("Invalid rule file");
    }

    auto rules_node = doc["rules"];
    for (auto it = rules_node.begin(); it != rules_node.end(); ++it) {
        YAML::Node rule_node = *it;
        auto id = rule_node["id"].as<std::string>();
        rules_[id] = rule_node;
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

namespace {
void ddwaf_result_destroy(ddwaf_result *res)
{
    ddwaf_result_free(res);
    delete res;
}
}

bool test_runner::run_test(const YAML::Node &runs)
{
    bool passed = false;
    std::unique_ptr<std::remove_pointer<ddwaf_context>::type,
        decltype(&ddwaf_context_destroy)>
        ctx(ddwaf_context_init(handle_, ddwaf_object_free),
            ddwaf_context_destroy);

    std::unique_ptr<ddwaf_result, decltype(&ddwaf_result_destroy)> res{
        new ddwaf_result{false, nullptr, 0}, ddwaf_result_destroy};

    try {
        expect(true, runs.IsDefined());
        expect(true, runs.size() > 0);
        for (auto it = runs.begin(); it != runs.end(); ++it) {
            YAML::Node run = *it;
            DDWAF_RET_CODE code = DDWAF_GOOD;
            if (run["code"].as<std::string>() == "monitor") {
                code = DDWAF_MONITOR;
            }

            auto object = run["input"].as<ddwaf_object>();
            auto retval = ddwaf_run(ctx.get(), &object, res.get(), timeout);

            expect(retval, code);
            if (code == DDWAF_MONITOR) {
                validate(run["rules"], YAML::Load(res->data));
            }

            ddwaf_result_free(res.get());
        }
        passed = true;
    } catch (const std::exception &e) {
        error_ << e.what();
    } catch (...) {
        error_ << "unknown exception";
    }

    if (!passed && res->data != nullptr) {
        YAML::Emitter out(output_);
        out.SetIndent(2);
        out.SetMapFormat(YAML::Block);
        out.SetSeqFormat(YAML::Block);
        out << YAML::Load(res->data);
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

void test_runner::validate(
    const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected.size(), obtained.size());

    std::vector<bool> seen(obtained.size(), false);

    bool found_expected = false;
    for (const auto &expected_rule_matches: expected) {
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

            auto rule = rules_[id];
            validate_rule(rule, obtained_rule_match["rule"]);
            validate_conditions(
                rule["conditions"], obtained_rule_match["rule_matches"]);
            validate_matches(
                expected_rule_match, obtained_rule_match["rule_matches"]);
        }

        expect(true, found_expected);
    }

    for (bool v : seen) { expect(true, v); }
}

void test_runner::validate_rule(
    const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected["id"], obtained["id"]);
    expect(expected["name"], obtained["name"]);

    auto expected_tags = expected["tags"];
    auto obtained_tags = obtained["tags"];

    expect(expected_tags["type"], obtained_tags["type"]);
    expect(expected_tags["category"], obtained_tags["category"]);
}

void test_runner::validate_conditions(
    const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected.size(), obtained.size());

    // Iterate through matches, assume they are in the same order as rule
    // conditions for now.
    for (std::size_t i = 0; i < expected.size(); i++) {
        auto expected_cond = expected[i];
        auto obtained_cond = obtained[i];

        expect(expected_cond["operator"], obtained_cond["operator"]);

        auto op = expected_cond["operator"].as<std::string>();
        if (op == "match_regex") {
            expect(expected_cond["parameters"]["regex"].as<std::string>(),
                obtained_cond["operator_value"].as<std::string>());
        }
    }
}

void test_runner::validate_matches(
    const YAML::Node &expected, const YAML::Node &obtained)
{
    expect(expected.size(), obtained.size());

    // Iterate through matches, assume they are in the same order as rule
    // conditions for now.
    for (std::size_t i = 0; i < expected.size(); i++) {
        auto expected_match = expected[i];
        auto obtained_match = obtained[i]["parameters"][0];
        if (expected_match["address"].IsDefined()) {
            expect(expected_match["address"], obtained_match["address"]);
        }
        if (expected_match["key_path"].IsDefined()) {
            expect(expected_match["key_path"], obtained_match["key_path"]);
        }
        expect(expected_match["value"], obtained_match["value"]);
    }
}
