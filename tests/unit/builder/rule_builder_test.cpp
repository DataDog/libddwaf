// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "builder/rule_builder.hpp"
#include "common/gtest_utils.hpp"
#include "configuration/common/configuration.hpp"
#include "matcher/ip_match.hpp"
#include "parameter.hpp"

using namespace ddwaf;

namespace {

TEST(TestRuleBuilder, SimpleRule)
{
    test::expression_builder exp_builder(1);
    exp_builder.start_condition();
    exp_builder.add_argument();
    exp_builder.add_target("http.client_ip");
    exp_builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    rule_spec spec{true, core_rule::source_type::base, "Test rule", {{"type", "flow1"}},
        exp_builder.build(), {}};

    rule_builder builder{"test", spec};

    auto rule = builder.build({});
    EXPECT_NE(rule, nullptr);

    EXPECT_STRV(rule->get_id(), "test");
    EXPECT_TRUE(rule->is_enabled());
    EXPECT_STRV(rule->get_name(), "Test rule");
    EXPECT_TRUE(rule->get_actions().empty());
    EXPECT_EQ(rule->get_source(), core_rule::source_type::base);
    EXPECT_EQ(rule->get_module(), rule_module_category::waf);
    EXPECT_EQ(rule->get_verdict(), core_rule::verdict_type::monitor);
}

} // namespace
