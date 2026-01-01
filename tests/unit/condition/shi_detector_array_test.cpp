// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "condition/shi_detector.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST(TestShiDetectorArray, InvalidType)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root = object_builder_da::map(
        {{"server.sys.shell.cmd", object_builder_da::map()}, {"server.request.query", "whatever"}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestShiDetectorArray, EmptyResource)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root = object_builder_da::map({{"server.sys.shell.cmd", object_builder_da::array()},
        {"server.request.query", "whatever"}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestShiDetectorArray, InvalidTypeWithinArray)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};
    auto root = object_builder_da::map({{"server.request.query", "cat /etc/passwd"},
        {"server.sys.shell.cmd", object_builder_da::array({"ls", "-l", ";", 22,
                                     object_builder_da::map(), "cat /etc/passwd"})}});

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    EXPECT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
    EXPECT_STR(cache.match->args[0].resolved, "ls -l ; cat /etc/passwd");
    EXPECT_TRUE(cache.match->args[0].key_path.empty());

    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    EXPECT_STR(cache.match->args[1].resolved, "cat /etc/passwd");
    EXPECT_TRUE(cache.match->args[1].key_path.empty());

    EXPECT_STR(cache.match->highlights[0], "cat /etc/passwd");
}

TEST(TestShiDetectorArray, NoMatchAndFalsePositives)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"getconf", "PAGESIZE"}, R"(get)"},
        {{"cat", "hello"}, R"(hello)"},
        {{"file", "-b", "--mime",
             "'/tmp/ForumEntr-avec kedge20160204-37527-ctbhbi20160204-37527-tuzome.png'"},
            "file"},
        {{"file", "-b", "--mime",
             "'/tmp/ForumEntr-avec kedge20160204-37527-ctbhbi20160204-37527-tuzome.png'"},
            "file -e"},
        {{"echo", "hello"}, "b"},
        {{"phantomjs", "/vendor/assets/javascripts/highcharts/highcharts-convert.js", "-infile",
             "/app/tmp/highcharts/json/input.json", "-outfile",
             "/app/tmp/highcharts/png/survey_641_chart.png", "-width", "700", "2>&1"},
            "641"},
        {{"/usr/bin/generate.sh", "--margin-bottom", "20mm", "--margin-top", "27mm",
             "--print-media-type", "--header-html", "https://url/blabla-bla", "--footer-html",
             "https://url/blabla-bla", "https://url/blabla-bla", "-"},
            "blabla-bla"},
        {{"ls", "-l", "-r -t"}, "-r -t"},
        {{R"!({ ( $(echo ls) ) })!"}, "ls)"},
        {{R"!({ ( $(echo ls) ) } #)!", "cat /etc/passwd"}, "cat /etc/passwd)"},
        {{"ls", "-l $file", "&&", "cat /etc/passwd"}, "-l $file"},
        {{"ls -l $file ; cat /etc/passwd"}, "-l $file"},
        // This should match at some point
        {{"time", "ls -l"}, "ls -l"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder_da::map();
        root.emplace("server.request.query", param);
        auto array = root.emplace("server.sys.shell.cmd", object_builder_da::array());
        for (const auto &arg : resource) { array.emplace_back(arg); }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestShiDetectorArray, ExecutablesAndRedirections)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"ls", "/sqreensecure/home/zeta/repos/RubyAgentTests/weblog-rails4/public/", ";", "echo",
             R"("testing")", ";", "ls robots.txt"},
            R"(ls robots)"},
        {{"ls", ";echo hello"}, ";echo hello"},
        {{"ls", "2> file", ";", "echo", "hello"}, "2> file"},
        {{"ls", "&> file", ";", "echo", "hello"}, "&> file"},
        {{"$(<file) -l"}, "$(<file) -l"},
        {{"ls", "injection ls",
             ";"
             "injection ls"},
            "injection ls"},
        {{"ls", "$(<file) -l", ";", "$(<file) -l"}, "$(<file) -l"},
        // The first match is overlapping, the second one isn't
        {{"$(<file)", "-l", ";", "$(<file) -l"}, "$(<file) -l"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder_da::map();
        root.emplace("server.request.query", param);
        auto array = root.emplace("server.sys.shell.cmd", object_builder_da::array());
        std::string resource_str;
        for (const auto &arg : resource) {
            array.emplace_back(arg);
            if (!resource_str.empty()) {
                resource_str.append(" ");
            }
            resource_str.append(arg);
        }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorArray, OverlappingInjections)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"ls", "/sqreensecure/home/zeta/repos/RubyAgentTests/weblog-rails4/public/", ";", "echo",
             R"("testing")", ";", "ls", "robots.txt"},
            R"(ls robots)"},
        {{"ls", ";", "echo", "hello"}, "; echo hello"},
        {{"ls", "2>", "file", ";", "echo", "hello"}, "2> file"},
        {{"ls", "&>", "file", ";", "echo", "hello"}, "&> file"},
        {{"$(<file)", "-l"}, "$(<file) -l"},
        {{"ls", "injection", "ls", ";", "injection", "ls"}, "injection ls"},
        {{"ls", "$(<file)", "-l", ";", "$(<file)", "-l"}, "$(<file) -l"},
        {{"ls", "$(<file)", "-l", ";", "$(<file)", "-l"}, "; $(<file)"},
        {{"ls", "$(<file)", "-l", ";", "$(<file)", "-l"}, "$(<file) -"},
        {{"ls", "$(<file)", "-l", ";", "$(<file)", "-l"}, "; $(<file) -"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder_da::map();
        root.emplace("server.request.query", param);
        auto array = root.emplace("server.sys.shell.cmd", object_builder_da::array());

        std::string resource_str;
        for (const auto &arg : resource) {
            array.emplace_back(arg);
            if (!resource_str.empty()) {
                resource_str.append(" ");
            }
            resource_str.append(arg);
        }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    }
}

TEST(TestShiDetectorArray, InjectionsWithinCommandSubstitution)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"echo", R"!("$(cat /etc/passwd)")!"}, "cat /etc/passwd"},
        {{R"!($(cat /etc/passwd))!"}, "cat /etc/passwd"},
        {{"echo", R"!($(echo $(echo ls)))!"}, "$(echo $(echo ls))"},
        {{"echo", R"!($(echo $(echo ls)))!"}, "echo ls"},
        {{"ls", R"!(-l $(echo /etc/passwd))!"}, "-l $(echo /etc/passwd)"},
        {{"{", "(", "$(", R"!(echo ls)!", ")", ")", "}"}, "echo ls"},
        {{"{", "(", R"!($(echo ls))!", ")", "}"}, "$(echo ls)"},
        {{"{", R"!(( $(echo ls) ))!", "}"}, "( $(echo ls) )"},
        {{R"!({ ( $(echo ls) ) })!"}, "{ ( $(echo ls) ) }"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder_da::map();
        root.emplace("server.request.query", param);
        auto array = root.emplace("server.sys.shell.cmd", object_builder_da::array());

        std::string resource_str;
        for (const auto &arg : resource) {
            array.emplace_back(arg);
            if (!resource_str.empty()) {
                resource_str.append(" ");
            }
            resource_str.append(arg);
        }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorArray, InjectionsWithinProcessSubstitution)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"echo", ">(ls -l))"}, "ls -l"},
        {{"diff", "<(file)", "<(rm -rf /etc/systemd/))"}, "rm -rf /etc/systemd/"},
    };

    for (const auto &[resource, param] : samples) {
        auto root = object_builder_da::map();
        root.emplace("server.request.query", param);
        auto array = root.emplace("server.sys.shell.cmd", object_builder_da::array());

        std::string resource_str;
        for (const auto &arg : resource) {
            array.emplace_back(arg);
            if (!resource_str.empty()) {
                resource_str.append(" ");
            }
            resource_str.append(arg);
        }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

TEST(TestShiDetectorArray, OffByOnePayloadsMatch)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"cat", "hello>", "cat", "/etc/passwd", ";", "echo", R"("")"}, R"(hello>)"},
        {{"cat hello>", "cat", "/etc/passwd", ";", "echo", R"("")"}, R"(t hello)"},
        {{"cat hello", ">", "cat", "/etc/passwd", ";", "echo", R"("")"}, R"(cat hello)"},
        {{"diff", "<(file)", "<(rm -rf /etc/systemd/)"}, "rm -"},
        {{"diff", "<(file)", "<(rm -rf /etc/systemd/)"}, "rm -"},
        {{"ls -l", "-a", "--classify", "--full-time"}, "ls -l"},
        {{"ls -l", "-a", "--classify", "--full-time", ";", "cat /etc/passwd"}, "cat /etc/passwd"},
        {{"ls -l", "-a", "--classify ; cat /etc/passwd #", "--full-time"}, "; cat /etc/passwd"},
        {{"l", "-l", "-a", ";", "l -l"}, "l -l"}};

    for (const auto &[resource, param] : samples) {
        auto root = object_builder_da::map();
        root.emplace("server.request.query", param);
        auto array = root.emplace("server.sys.shell.cmd", object_builder_da::array());

        std::string resource_str;
        for (const auto &arg : resource) {
            array.emplace_back(arg);
            if (!resource_str.empty()) {
                resource_str.append(" ");
            }
            resource_str.append(arg);
        }

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param);
    }
}

} // namespace
