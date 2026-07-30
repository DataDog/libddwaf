// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "condition/sqli_detector.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

class DialectTestFixture : public ::testing::TestWithParam<std::string> {};

INSTANTIATE_TEST_SUITE_P(
    TestSqliDetector, DialectTestFixture, ::testing::Values("mysql", "sqlite", "postgresql"));

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST_P(DialectTestFixture, InvalidSql)
{
    auto dialect = GetParam();

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(]    [)", "   ["},
        {R"(&   &[)", "  &["},
    };

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", dialect}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    }
}

TEST_P(DialectTestFixture, InjectionWithoutTokens)
{
    auto dialect = GetParam();

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(SELECT ][ FROM table;)", "]["},
        {R"(SELECT && FROM table;)", "&&"},
    };

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", dialect}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    }
}

TEST_P(DialectTestFixture, BenignInjections)
{
    auto dialect = GetParam();

    std::vector<std::pair<std::string, std::string>> samples{
        {
            R"(SELECT scale_grades.weight
               FROM grades
               LEFT JOIN markbook_students USING (markbook_student_id)
               LEFT JOIN markbook_columns ON (grades.task_id = markbook_columns.task_id)
               LEFT JOIN 4_blabla.scale_grades ON (grades.scale_grade_id = scale_grades.scale_grade_id)
               WHERE markbook_column_id = '4242'
               AND markbook_class_id = '4242'
               AND markbook_students.inactive IS NULL)",
            "4242"},
        {R"(SELECT values FROM table WHERE column IN (1, 2, 3, 4, 5);)", "(1, 2, 3, 4, 5)"},
        {R"(SELECT values FROM table WHERE id=-- admin)", "-- admin"},
        {R"(SELECT values FROM table WHERE value IN (-1,-2,+3,+4);)", "-1,-2,+3,+4"},
        {"SELECT * FROM ships WHERE id=input -", "input -"},
    };

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", dialect}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    }
}

TEST_P(DialectTestFixture, MaliciousInjections)
{
    auto dialect = GetParam();

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    std::vector<std::tuple<std::string, std::string, std::string>> samples{
        {R"(SELECT * FROM users ORDER BY db.table notAsc)",
            R"(SELECT * FROM users ORDER BY db.table notAsc)", R"(db.table notAsc)"},
        {R"(SELECT * FROM users ORDER BY 1.col, 2, 'str')",
            R"(SELECT * FROM users ORDER BY ?.col, ?, ?)", R"(1.col, 2, 'str')"},
        {R"(SELECT * FROM users ORDER BY table.col OFFSET 0'')",
            R"(SELECT * FROM users ORDER BY table.col OFFSET ??)", R"(table.col OFFSET 0')"},
        {R"(SELECT * FROM users ORDER BY table.col ASC LIMIT)",
            R"(SELECT * FROM users ORDER BY table.col ASC LIMIT)", R"(table.col ASC LIMIT)"},
        {R"(SELECT * FROM users ORDER table.col ASC)", R"(SELECT * FROM users ORDER table.col ASC)",
            R"(table.col ASC)"},
        {R"(SELECT * FROM users ORDER BY UPPER(db.table) ASC)",
            R"(SELECT * FROM users ORDER BY UPPER(db.table) ASC)", R"(UPPER(db.table) ASC)"},
        {R"(SELECT * FROM users ORDER
            BY table.col OFFSET 0'')",
            R"(SELECT * FROM users ORDER
            BY table.col OFFSET ??)",
            R"(table.col OFFSET 0')"},
        {R"(SELECT * FROM ships WHERE name LIKE '%neb%')",
            R"(SELECT * FROM ships WHERE name LIKE ?)", R"(SELECT * FROM ships WHERE)"},
        {"\n                SELECT id, author, title, body, created_at\n                FROM posts "
         "\nWHERE id = 1 OR 1 = 1",
            "\n                SELECT id, author, title, body, created_at\n                FROM "
            "posts \nWHERE id = ? OR ? = ?",
            "1 OR 1 = 1"},
        {"SELECT * FROM neb UNION SELECT 1,'\u0099',3,4,5,6 FROM dual",
            "SELECT * FROM neb UNION SELECT ?,?,?,?,?,? FROM dual", "SELECT 1,'\u0099',"},
    };

    for (const auto &[statement, obfuscated, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", dialect}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, obfuscated);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST_P(DialectTestFixture, Tautologies)
{
    auto dialect = GetParam();

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    std::vector<std::tuple<std::string, std::string, std::string>> samples{
        {"SELECT x FROM t WHERE id = 1 OR 1", "SELECT x FROM t WHERE id = ? OR ?", "1 OR 1"},
        {"SELECT x FROM t WHERE id = 1 OR tbl", "SELECT x FROM t WHERE id = ? OR tbl", "1 OR tbl"},
        {"SELECT x FROM t WHERE id = tbl OR tbl", "SELECT x FROM t WHERE id = tbl OR tbl",
            "tbl OR tbl"},
        {"SELECT x FROM t WHERE id = tbl OR tbl", "SELECT x FROM t WHERE id = tbl OR tbl",
            "tbl OR tbl"},
        {"SELECT x FROM t WHERE id = ''OR''", "SELECT x FROM t WHERE id = ?OR?", "'OR'"},
        {"SELECT x FROM t WHERE id = 1||tbl", "SELECT x FROM t WHERE id = ?||tbl", "1||tbl"},
        {"SELECT x FROM t WHERE id = tbl||tbl", "SELECT x FROM t WHERE id = tbl||tbl", "tbl||tbl"},
        {R"(SELECT x FROM t WHERE id = ''||'')", R"(SELECT x FROM t WHERE id = ?||?)", R"('||')"},
        {"SELECT x FROM t WHERE id = 1 XOR 1", "SELECT x FROM t WHERE id = ? XOR ?", "1 XOR 1"},
        {R"(SELECT x FROM t WHERE id = tbl XOR tbl)", R"(SELECT x FROM t WHERE id = tbl XOR tbl)",
            "tbl XOR tbl"},
        {R"(SELECT x FROM t WHERE id = ''XOR'')", R"(SELECT x FROM t WHERE id = ?XOR?)",
            R"('XOR')"},
        {"SELECT x FROM t WHERE id = ''Or''", "SELECT x FROM t WHERE id = ?Or?", "'Or'"},
        {"SELECT x FROM t WHERE id = '1' or 1 = 1", "SELECT x FROM t WHERE id = ? or ? = ?",
            "1 = 1"},
        {"SELECT x FROM t WHERE id = '1' or 1 = '1'", "SELECT x FROM t WHERE id = ? or ? = ?",
            "1 = '1'"},
        {"SELECT x FROM t WHERE id = '1' or (1) = (1)", "SELECT x FROM t WHERE id = ? or (?) = (?)",
            "(1) = (1)"},
        {"SELECT x FROM t WHERE id = '1' or (0x22) = (1)",
            "SELECT x FROM t WHERE id = ? or (?) = (?)", "(0x22) = (1)"},
        {"SELECT x FROM t WHERE id = '1' or (1) = ('1')",
            "SELECT x FROM t WHERE id = ? or (?) = (?)", "(1) = ('1')"},
        {R"(SELECT * FROM ships WHERE name LIKE '%neb%' OR 1=1)",
            R"(SELECT * FROM ships WHERE name LIKE ? OR ?=?)", R"(neb%' OR 1=1)"},
        {
            R"(-- 'something' OR 1=1; --
            SELECT * FROM table WHERE id='' OR 1=1; --)",
            R"(-- 'something' OR 1=1; --
            SELECT * FROM table WHERE id=? OR ?=?; --)",
            "' OR 1=1; --",
        },
    };

    for (const auto &[statement, obfuscated, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", dialect}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, obfuscated);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST_P(DialectTestFixture, Comments)
{
    auto dialect = GetParam();

    std::vector<std::tuple<std::string, std::string, std::string>> samples{
        {R"(SELECT x FROM t WHERE id='admin'--)", R"(SELECT x FROM t WHERE id=?--)", R"(admin'--)"},
        {R"(SELECT x FROM t WHERE id='admin')--)", R"(SELECT x FROM t WHERE id=?)--)",
            R"(admin')--)"},
        {R"(SELECT x FROM t WHERE id=1-- )", R"(SELECT x FROM t WHERE id=?-- )", R"(1-- )"},
        {R"(SELECT x FROM t WHERE id=''-- AND pwd='pwd'''--)",
            R"(SELECT x FROM t WHERE id=?-- AND pwd='pwd'''--)", R"('--)"},
        {R"(SELECT * FROM ships WHERE id= 1 -- AND password=HASH('str') 1 --)",
            R"(SELECT * FROM ships WHERE id= ? -- AND password=HASH('str') 1 --)", R"( 1 --)"},
        {"SELECT * FROM ships WHERE id=-- \n1 OR 1", "SELECT * FROM ships WHERE id=-- \n? OR ?",
            "-- \n1 OR 1"},
    };

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, obfuscated, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", dialect}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, obfuscated);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST(TestSqliDetectorMySql, Comments)
{
    std::vector<std::tuple<std::string, std::string, std::string>> samples{
        {R"(SELECT x FROM t WHERE id='admin'#)", R"(SELECT x FROM t WHERE id=?#)", R"(admin'#)"},
        {R"(SELECT x FROM t WHERE id='admin')#)", R"(SELECT x FROM t WHERE id=?)#)", R"(admin')#)"},
        {R"(SELECT x FROM t WHERE id=1# )", R"(SELECT x FROM t WHERE id=?# )", R"(1# )"},
        {R"(SELECT x FROM t WHERE id=''# AND pwd='pwd'''# )",
            R"(SELECT x FROM t WHERE id=?# AND pwd='pwd'''# )", R"('# )"},
        {R"(SELECT * FROM ships WHERE id= 1 # AND password=HASH('str') 1 #)",
            R"(SELECT * FROM ships WHERE id= ? # AND password=HASH('str') 1 #)", R"( 1 #)"},
        {"SELECT * FROM ships WHERE id=# \n1 OR 1", "SELECT * FROM ships WHERE id=# \n? OR ?",
            "# \n1 OR 1"},
    };

    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};
    for (const auto &[statement, obfuscated, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", "mysql"}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, obfuscated);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST(TestSqliDetectorMySql, Tautologies)
{
    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    std::vector<std::tuple<std::string, std::string, std::string>> samples{
        {R"(SELECT x FROM t WHERE id = ""OR"")", R"(SELECT x FROM t WHERE id = ?OR?)", R"("OR")"},
        {R"(SELECT x FROM t WHERE id = ""||"")", R"(SELECT x FROM t WHERE id = ?||?)", R"("||")"},
        {R"(SELECT x FROM t WHERE id = ""XOR"")", R"(SELECT x FROM t WHERE id = ?XOR?)",
            R"("XOR")"},
        {R"(SELECT x FROM t WHERE id = ""Or"")", R"(SELECT x FROM t WHERE id = ?Or?)", R"("Or")"},
        {R"(SELECT x FROM t WHERE id = "1" or 1 = "1")", R"(SELECT x FROM t WHERE id = ? or ? = ?)",
            R"(1 = "1")"},
        {R"(SELECT x FROM t WHERE id = "1" or '1' = "1")",
            R"(SELECT x FROM t WHERE id = ? or ? = ?)", R"('1' = "1")"},
        {R"(SELECT x FROM t WHERE id = "1" or ("1") = ('1'))",
            R"(SELECT x FROM t WHERE id = ? or (?) = (?))", R"(("1") = ('1'))"},
    };

    for (const auto &[statement, obfuscated, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", "mysql"}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, obfuscated);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST(TestSqliDetectorPgSql, Tautologies)
{
    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    std::vector<std::tuple<std::string, std::string, std::string>> samples{
        {R"(SELECT x FROM t WHERE id = $$$$OR$$$$)", R"(SELECT x FROM t WHERE id = ?OR?)",
            R"($$OR$$)"},
        {R"(SELECT x FROM t WHERE id = $$$$||$$$$)", R"(SELECT x FROM t WHERE id = ?||?)",
            R"($$||$$)"},
        {R"(SELECT x FROM t WHERE id = $$$$XOR$$$$)", R"(SELECT x FROM t WHERE id = ?XOR?)",
            R"($$XOR$$)"},
        {R"(SELECT x FROM t WHERE id = '1' or 1 = $tag$1$tag$)",
            R"(SELECT x FROM t WHERE id = ? or ? = ?)", R"(1 = $tag$1$tag$)"},
        {R"(SELECT x FROM t WHERE id = '1' or 0x1 = $tag$1$tag$)",
            R"(SELECT x FROM t WHERE id = ? or ? = ?)", R"(0x1 = $tag$1$tag$)"},
        {R"(SELECT x FROM t WHERE id = '1' or '1' = $$1$$)",
            R"(SELECT x FROM t WHERE id = ? or ? = ?)", R"('1' = $$1$$)"},
        {R"(SELECT x FROM t WHERE id = '1' or ($value$1$value$) = ($$1$$))",
            R"(SELECT x FROM t WHERE id = ? or (?) = (?))", R"(($value$1$value$) = ($$1$$))"},
    };

    for (const auto &[statement, obfuscated, input] : samples) {
        auto root = object_builder_da::map({{"server.db.statement", statement},
            {"server.db.system", "pgsql"}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
        EXPECT_STR(cache.match->args[0].resolved, obfuscated);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

// Generates the parameter definition of the sqli detector, applying the given
// transformers to the params argument only
std::vector<condition_parameter> gen_sqli_param_def_with_transformers(
    std::vector<transformer_id> transformers)
{
    return {condition_parameter{{condition_target{
                .name = "server.db.statement", .index = get_target_index("server.db.statement")}}},
        condition_parameter{{condition_target{.name = "server.request.query",
            .index = get_target_index("server.request.query"),
            .key_path = {},
            .transformers = std::move(transformers)}}},
        condition_parameter{{condition_target{
            .name = "server.db.system", .index = get_target_index("server.db.system")}}}};
}

constexpr std::string_view sqli_statement = R"(SELECT * FROM t WHERE id = '' OR '1'='1')";
constexpr std::string_view sqli_obfuscated = R"(SELECT * FROM t WHERE id = ? OR ?=?)";
constexpr std::string_view sqli_payload = R"(' OR '1'='1)";

TEST(TestSqliDetectorTransformers, NoMatchWithoutTransformer)
{
    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.system")}};

    auto root = object_builder_da::map({{"server.db.statement", sqli_statement},
        {"server.db.system", "mysql"}, {"server.request.query", "%27%20OR%20%271%27%3D%271"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

TEST(TestSqliDetectorTransformers, MatchWithTransformer)
{
    sqli_detector cond{gen_sqli_param_def_with_transformers({transformer_id::url_decode})};

    auto root = object_builder_da::map({{"server.db.statement", sqli_statement},
        {"server.db.system", "mysql"}, {"server.request.query", "%27%20OR%20%271%27%3D%271"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.db.statement");
    EXPECT_STR(cache.match->args[0].resolved, sqli_obfuscated);

    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    // The reported parameter is the transformed one
    EXPECT_STR(cache.match->args[1].resolved, sqli_payload);
    EXPECT_STR(cache.match->highlights[0], sqli_payload);
}

TEST(TestSqliDetectorTransformers, MatchWithMultipleTransformers)
{
    sqli_detector cond{gen_sqli_param_def_with_transformers(
        {transformer_id::base64_decode, transformer_id::url_decode})};

    // base64("%27%20OR%20%271%27%3D%271")
    auto root = object_builder_da::map(
        {{"server.db.statement", sqli_statement}, {"server.db.system", "mysql"},
            {"server.request.query", "JTI3JTIwT1IlMjAlMjcxJTI3JTNEJTI3MQ=="}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], sqli_payload);
}

// When the transformers leave the parameter untouched, the original value must
// still be evaluated
TEST(TestSqliDetectorTransformers, MatchWithUnappliedTransformer)
{
    sqli_detector cond{gen_sqli_param_def_with_transformers({transformer_id::url_decode})};

    auto root = object_builder_da::map({{"server.db.statement", sqli_statement},
        {"server.db.system", "mysql"}, {"server.request.query", sqli_payload}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], sqli_payload);
}

// Every parameter within the container must be transformed independently
TEST(TestSqliDetectorTransformers, MatchWithTransformerWithinContainer)
{
    sqli_detector cond{gen_sqli_param_def_with_transformers({transformer_id::url_decode})};

    auto root = object_builder_da::map(
        {{"server.db.statement", sqli_statement}, {"server.db.system", "mysql"},
            {"server.request.query", object_builder_da::map({{"harmless", "not+an+injection"},
                                         {"payload", "%27%20OR%20%271%27%3D%271"}})}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], sqli_payload);
    ASSERT_EQ(cache.match->args[1].key_path.size(), 1);
    EXPECT_STR(std::get<std::string_view>(cache.match->args[1].key_path[0]), "payload");
}

// Neither the statement nor the database type are transformed
TEST(TestSqliDetectorTransformers, ResourceNotTransformed)
{
    sqli_detector cond{{condition_parameter{{condition_target{.name = "server.db.statement",
                            .index = get_target_index("server.db.statement"),
                            .key_path = {},
                            .transformers = {transformer_id::url_decode}}}},
        condition_parameter{{condition_target{
            .name = "server.request.query", .index = get_target_index("server.request.query")}}},
        condition_parameter{{condition_target{
            .name = "server.db.system", .index = get_target_index("server.db.system")}}}}};

    auto root = object_builder_da::map(
        {{"server.db.statement", R"(SELECT%20*%20FROM%20t%20WHERE%20id%20=%20''%20OR%20'1'='1')"},
            {"server.db.system", "mysql"}, {"server.request.query", sqli_payload}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

// The transformed parameter replaces the original one, so a payload which is
// present verbatim within the statement is no longer detected once the
// transformers modify it
TEST(TestSqliDetectorTransformers, NoMatchOnUntransformedParameter)
{
    sqli_detector cond{gen_sqli_param_def_with_transformers({transformer_id::lowercase})};

    auto root = object_builder_da::map({{"server.db.statement", sqli_statement},
        {"server.db.system", "mysql"}, {"server.request.query", sqli_payload}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

// A parameter reduced to an empty string by the transformers must not be
// considered an injection
TEST(TestSqliDetectorTransformers, NoMatchOnEmptyTransformedParameter)
{
    sqli_detector cond{gen_sqli_param_def_with_transformers({transformer_id::remove_nulls})};

    const std::string nulls("\0\0\0\0", 4);
    auto root = object_builder_da::map({{"server.db.statement", sqli_statement},
        {"server.db.system", "mysql"}, {"server.request.query", nulls}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

} // namespace
