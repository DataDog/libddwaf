// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/sqli_detector.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

class DialectTestFixture : public ::testing::TestWithParam<std::string> {};

INSTANTIATE_TEST_SUITE_P(
    TestSqliDetector, DialectTestFixture, ::testing::Values("mysql", "sqlite", "postgresql"));

template <typename... Args> std::vector<parameter_definition> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST_P(DialectTestFixture, Identifiers)
{
    auto dialect = GetParam();

    std::vector<std::pair<std::string, std::string>> samples{{
        R"(SELECT scale_grades.weight
               FROM grades
               LEFT JOIN markbook_students USING (markbook_student_id)
               LEFT JOIN markbook_columns ON (grades.task_id = markbook_columns.task_id)
               LEFT JOIN 4_blabla.scale_grades ON (grades.scale_grade_id = scale_grades.scale_grade_id)
               WHERE markbook_column_id = '4242'
               AND markbook_class_id = '4242'
               AND markbook_students.inactive IS NULL)",
        "4242"}};

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, input] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(
            &root, "server.db.statement", ddwaf_object_string(&tmp, statement.c_str()));
        ddwaf_object_map_add(&root, "server.db.system", ddwaf_object_string(&tmp, dialect.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome) << statement;
    }
}

TEST_P(DialectTestFixture, Injections)
{
    auto dialect = GetParam();

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(SELECT * FROM users ORDER BY db.table notAsc)", R"(db.table notAsc)"},
        {R"(SELECT * FROM users ORDER BY 1.col, 2, "str")", R"(1.col, 2, "str")"},
        {R"(SELECT * FROM users ORDER BY table.col OFFSET 0")", R"(table.col OFFSET 0)"},
        {R"(SELECT * FROM ships WHERE name LIKE '%neb%'")", R"(SELECT * FROM ships WHERE)"},
        {"\n                SELECT id, author, title, body, created_at\n                FROM posts "
         "WHERE id = 1 OR 1 = 1",
            "1 OR 1 = 1"}};

    for (const auto &[statement, input] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(
            &root, "server.db.statement", ddwaf_object_string(&tmp, statement.c_str()));
        ddwaf_object_map_add(&root, "server.db.system", ddwaf_object_string(&tmp, dialect.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << statement;
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, statement.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input.c_str());
    }
}

TEST_P(DialectTestFixture, Tautologies)
{
    auto dialect = GetParam();

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {"SELECT x FROM t WHERE id = 1 OR 1", "1 OR 1"},
        {"SELECT x FROM t WHERE id = 1 OR tbl", "1 OR tbl"},
        {"SELECT x FROM t WHERE id = tbl OR tbl", "tbl OR tbl"},
        {"SELECT x FROM t WHERE id = tbl OR tbl", "tbl OR tbl"},
        {R"(SELECT x FROM t WHERE id = ""OR"")", R"("OR")"},
        {"SELECT x FROM t WHERE id = ''OR''", "'OR'"},
        {"SELECT x FROM t WHERE id = 1||tbl", "1||tbl"},
        {"SELECT x FROM t WHERE id = tbl||tbl", "tbl||tbl"},
        {R"(SELECT x FROM t WHERE id = ""||"")", R"("||")"},
        {"SELECT x FROM t WHERE id = 1 XOR 1", "1 XOR 1"},
        {R"(SELECT x FROM t WHERE id = tbl XOR tbl)", "tbl XOR tbl"},
        {R"(SELECT x FROM t WHERE id = ""XOR"")", R"("XOR")"},
        {"SELECT x FROM t WHERE id = ''Or''", "'Or'"},
        {"SELECT x FROM t WHERE id = '1' or 1 = 1", "1 = 1"},
        {"SELECT x FROM t WHERE id = '1' or 1 = '1'", "1 = '1'"}};

    for (const auto &[statement, input] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(
            &root, "server.db.statement", ddwaf_object_string(&tmp, statement.c_str()));
        ddwaf_object_map_add(&root, "server.db.system", ddwaf_object_string(&tmp, dialect.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << statement;
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, statement.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input.c_str());
    }
}

TEST_P(DialectTestFixture, Comments)
{
    auto dialect = GetParam();

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(SELECT x FROM t WHERE id='admin'--)", R"(admin'--)"},
        {R"(SELECT x FROM t WHERE id='admin')--)", R"(admin')--)"},
        {R"(SELECT x FROM t WHERE id=1-- )", R"(1-- )"},
        {R"(SELECT x FROM t WHERE id=''-- AND pwd='pwd'''--)", R"('--)"},
        {R"(SELECT * FROM ships WHERE id= 1 --AND password=HASH('str') 1 --)", R"( 1 --)"},
        //{R"(SELECT x FROM t WHERE id='admin'#)", R"(admin'#)"},
        //{R"(SELECT x FROM t WHERE id='admin')#)", R"(admin')#)"},
        //{R"(SELECT * FROM ships WHERE id= 1 # AND password=HASH('str') 1 # )", R"( 1 # )"},
    };

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, input] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(
            &root, "server.db.statement", ddwaf_object_string(&tmp, statement.c_str()));
        ddwaf_object_map_add(&root, "server.db.system", ddwaf_object_string(&tmp, dialect.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << statement;
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, statement.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input.c_str());
    }
}

/*TEST(TestSqliDetectorSqlite, Basic)*/
/*{*/
/*}*/
/*TEST_P(DialectTestFixturePostgreSql, FalsePositives)*/
/*{*/
/*std::vector<std::pair<std::string, std::string>> samples{*/
/*{R"(SELECT unnest($1::text[]) FROM users)", "[]"},*/
/*{R"(SELECT  "users".* FROM "users" WHERE (id = \'506441\') ORDER BY "users"."id" ASC LIMIT ?
 * OFFSET ?)",*/
/*"id = '506441'"}};*/

/*sqli_detector cond{*/
/*{gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};*/
/*for (const auto &[statement, input] : samples) {*/
/*ddwaf_object tmp;*/
/*ddwaf_object root;*/

/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(*/
/*&root, "server.db.statement", ddwaf_object_string(&tmp, statement.c_str()));*/
/*ddwaf_object_map_add(&root, "server.db.system", ddwaf_object_string(&tmp, "postgresql"));*/
/*ddwaf_object_map_add(*/
/*&root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));*/

/*object_store store;*/
/*store.insert(root);*/

/*ddwaf::timer deadline{2s};*/
/*condition_cache cache;*/
/*auto res = cond.eval(cache, store, {}, {}, deadline);*/
/*ASSERT_FALSE(res.outcome) << statement;*/
/*}*/
/*}*/

/*TEST_P(DialectTestFixtureMySql, Injections)*/
/*{*/
/*sqli_detector cond{*/
/*{gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};*/

/*std::vector<std::pair<std::string, std::string>> samples{*/
/*{R"(SELECT * FROM users ORDER BY db.table ASC LIMIT 42)", R"(db.table ASC LIMIT)"},*/
/*};*/

/*for (const auto &[statement, input] : samples) {*/
/*ddwaf_object tmp;*/
/*ddwaf_object root;*/

/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(*/
/*&root, "server.db.statement", ddwaf_object_string(&tmp, statement.c_str()));*/
/*ddwaf_object_map_add(&root, "server.db.system", ddwaf_object_string(&tmp, "mysql"));*/
/*ddwaf_object_map_add(*/
/*&root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));*/

/*object_store store;*/
/*store.insert(root);*/

/*ddwaf::timer deadline{2s};*/
/*condition_cache cache;*/
/*auto res = cond.eval(cache, store, {}, {}, deadline);*/
/*ASSERT_TRUE(res.outcome) << statement;*/
/*EXPECT_FALSE(res.ephemeral);*/

/*EXPECT_TRUE(cache.match);*/
/*EXPECT_STRV(cache.match->args[0].address, "server.db.statement");*/
/*EXPECT_STR(cache.match->args[0].resolved, statement.c_str());*/
/*EXPECT_TRUE(cache.match->args[0].key_path.empty());*/

/*EXPECT_STRV(cache.match->args[1].address, "server.request.query");*/
/*EXPECT_STR(cache.match->args[1].resolved, input.c_str());*/
/*EXPECT_TRUE(cache.match->args[1].key_path.empty());*/

/*EXPECT_STR(cache.match->highlights[0], input.c_str());*/
/*}*/
/*}*/

} // namespace
