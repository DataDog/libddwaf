// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ruleset.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {
core_rule make_rule(std::string id, std::string name,
    std::unordered_map<std::string, std::string> tags, std::vector<std::string> actions,
    core_rule::source_type source = core_rule::source_type::base)
{
    return {std::move(id), std::move(name), std::move(tags), std::make_shared<expression>(),
        std::move(actions), true, source};
}

TEST(TestRuleset, InsertSingleRegularBaseRules)
{
    auto rules = std::make_shared<std::vector<core_rule>>();
    rules->emplace_back(
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {}));
    rules->emplace_back(
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {}));
    rules->emplace_back(
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {}));
    rules->emplace_back(
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {}));
    rules->emplace_back(
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {}));
    rules->emplace_back(
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {}));

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, std::make_shared<std::vector<core_rule>>());

        EXPECT_EQ(ruleset.base_rules->size(), 6);
    }
}

/*TEST(TestRuleset, InsertSinglePriorityBaseRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"})*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSingleMixedBaseRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}},
 * {}));*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}},
 * {}));*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}},
 * {}));*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"})*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSingleRegularUserRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {},*/
/*core_rule::source_type::user)*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/

/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSinglePriorityUserRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user)*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSingleMixedUserRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user)*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSingleRegularMixedRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::base),*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::base),*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {},*/
/*core_rule::source_type::base),*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {},*/
/*core_rule::source_type::user)*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSinglePriorityMixedRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::base),*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::base),*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::base),*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user)*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 6);*/
/*}*/
/*}*/

/*TEST(TestRuleset, InsertSingleMixedMixedRules)*/
/*{*/
/*std::vector<core_rule> rules = {*/
/*rules.emplace_back(make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"},*/
/*core_rule::source_type::user),*/
/*rules.emplace_back(make_rule("id6", "name", {{"type", "type0"}, {"category", "category0"}},
 * {}));*/
/*rules.emplace_back(make_rule("id7", "name", {{"type", "type1"}, {"category", "category0"}},
 * {}));*/
/*rules.emplace_back(make_rule("id8", "name", {{"type", "type1"}, {"category", "category0"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id9", "name", {{"type", "type2"}, {"category", "category0"}},
 * {}));*/
/*rules.emplace_back(make_rule("id10", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"}));*/
/*rules.emplace_back(make_rule("id11", "name", {{"type", "type2"}, {"category", "category1"}},
 * {"block"})*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 12);*/
/*}*/

/*{*/
/*ddwaf::ruleset ruleset;*/
/*ruleset.insert_rules(rules, {});*/

/*EXPECT_EQ(ruleset.base_rules->size(), 12);*/
/*}*/
/*}*/

} // namespace
