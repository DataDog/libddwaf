// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "condition/shi_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST(TestShiDetectorString, InvalidType)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root = object_builder::map(
        {{"server.sys.shell.cmd", owned_object{}}, {"server.request.query", "whatever"}});

    object_store store;
    store.insert(std::move(root), evaluation_scope::context());

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestShiDetectorString, EmptyResource)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root =
        object_builder::map({{"server.sys.shell.cmd", ""}, {"server.request.query", "whatever"}});

    object_store store;
    store.insert(std::move(root), evaluation_scope::context());

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestShiDetectorString, NoMatchAndFalsePositives)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(getconf PAGESIZE)", R"(get)"},
        {R"(cat hello)", R"(hello)"},
        {R"(file -b --mime '/tmp/ForumEntr-avec kedge20160204-37527-ctbhbi20160204-37527-tuzome.png')",
            "file"},
        {R"(file -b --mime '/tmp/ForumEntr-avec kedge20160204-37527-ctbhbi20160204-37527-tuzome.png')",
            "file -e"},
        {R"(echo hello)", "b"},
        {R"(phantomjs /vendor/assets/javascripts/highcharts/highcharts-convert.js -infile /app/tmp/highcharts/json/input.json -outfile /app/tmp/highcharts/png/survey_641_chart.png -width 700 2>&1)",
            "641"},
        {R"(/usr/bin/generate.sh --margin-bottom 20mm --margin-top 27mm --print-media-type --header-html https://url/blabla-bla --footer-html https://url/blabla-bla https://url/blabla-bla -)",
            "blabla-bla"},
        {R"(ls -l -r -t)", "-r -t"},
        {R"!({ ( $(echo ls) ) })!", "ls)"},
        {R"!({ ( $(echo ls) ) } # cat /etc/passwd)!", "cat /etc/passwd"},
        {R"!(ls -l file && cat /etc/passwd)!", "-l file"},
        {R"!("ls -l $file ; cat /etc/passwd)!", "-l $file"},
        // This should match at some point
        {R"!(time ls -l)!", "ls -l"},

    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome) << resource;
    }
}

TEST(TestShiDetectorString, ExecutablesAndRedirections)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"( ls /sqreensecure/home/zeta/repos/RubyAgentTests/weblog-rails4/public/; echo "testing"; ls robots.txt)",
            R"( echo "testing"; ls robots)"},
        {"ls; echo hello", "echo hello"},
        {"ls 2> file; echo hello", "2> file"},
        {"ls &> file; echo hello", "&> file"},
        {"$(<file) -l", "$(<file) -l"},
        {"ls injection ls; injection ls", "injection ls"},
        {"ls $(<file) -l ; $(<file) -l", "$(<file) -l"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << resource;
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorString, InjectionsWithinCommandSubstitution)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"!(echo "$(cat /etc/passwd)")!", "cat /etc/passwd"},
        {R"!($(cat /etc/passwd))!", "cat /etc/passwd"},
        {R"!($(echo $(echo $(echo ls))))!", "$(echo $(echo ls))"},
        {R"!($(echo $(echo $(echo ls))))!", "echo ls"},
        {R"!(ls -l $(echo /etc/passwd))!", "-l $(echo /etc/passwd)"},
        {R"!({ ( $(echo ls) ) })!", "echo ls"},
        {R"!({ ( $(echo ls) ) })!", "$(echo ls)"},
        {R"!({ ( $(echo ls) ) })!", "( $(echo ls) )"},
        {R"!({ ( $(echo ls) ) })!", "{ ( $(echo ls) ) }"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << resource;
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorString, InjectionsWithinProcessSubstitution)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"!(echo >(ls -l))!", "ls -l"},
        {R"!(diff <(file) <(rm -rf /etc/systemd/))!", "rm -rf /etc/systemd/"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << resource;
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorString, OffByOnePayloadsMatch)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(cat hello> cat /etc/passwd; echo "")", R"(hello>)"},
        {R"(cat hello> cat /etc/passwd; echo "")", R"(t hello)"},
        {R"(cat hello> cat /etc/passwd; echo "")", R"(cat hello)"},
        {R"!(diff <(file) <(rm -rf /etc/systemd/))!", "rm -"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << resource;
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorString, MultipleArgumentsMatch)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::string params = R"({
        post: {
            blank: "",
            name: "Create",
            other: "hello",
            other2: "hello; ls /etc/passwd",
            other3: "hello\"; cat /etc/passwd; echo \"",
            other4: "\"hello\\\\\"; cat /etc/passwd; echo",
            other5: "1.json 2> /tmp/toto",
            other6: "1.json > /tmp/toto",
            other7: "google.com; ls",
            other8: "google.com; ${a:-ls}",
            other9: "google.com; TOTO=ls ${a:-$TOTO}",
            other10: "google.com; TOTO=ls $TOTO"
        }
    })";

    std::vector<std::string> samples{
        R"(cat hello; ls /etc/passwd)",
        R"(cat "hello"; cat /etc/passwd; echo "")",
        R"(ping -c 1 google.com; ls)",
        R"(cat "hello\\"; cat /etc/passwd; echo ")",
        R"(ls public/1.json 2> /tmp/toto)",
        R"(ls public/1.json > /tmp/toto)",
        R"(ping -c 1 google.com; ${a:-ls})",
        R"(ping -c 1 google.com; TOTO=ls ${a:-$TOTO})",
        R"(ping -c 1 google.com; TOTO=ls $TOTO)",

    };

    for (const auto &resource : samples) {
        auto root = object_builder::map({{"server.sys.shell.cmd", resource},
            {"server.request.query", yaml_to_object<owned_object>(params)}});

        object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << resource;
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());
    }
}

} // namespace
