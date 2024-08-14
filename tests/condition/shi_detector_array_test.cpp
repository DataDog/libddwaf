// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "condition/shi_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
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
    };

    for (const auto &[resource, param] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);

        ddwaf_object array;
        ddwaf_object_array(&array);
        for (const auto &arg : resource) {
            ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
        }
        ddwaf_object_map_add(&root, "server.sys.shell.cmd", &array);
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_FALSE(res.outcome) << param;
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
        {{"ls", "injection ls", ";" "injection ls"}, "injection ls"},
        {{"ls", "$(<file) -l", ";", "$(<file) -l"}, "$(<file) -l"},
    };

    for (const auto &[resource, param] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);

        std::string resource_str;
        ddwaf_object array;
        ddwaf_object_array(&array);
        for (const auto &arg : resource) {
            ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
            resource_str.append(arg); resource_str.append(" ");
        }
        ddwaf_object_map_add(&root, "server.sys.shell.cmd", &array);

        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << param;
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param.c_str());
    }
}

/*TEST(TestShiDetectorArray, InjectionsWithinCommandSubstitution)*/
/*{*/
/*shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};*/

/*std::vector<std::pair<std::string, std::string>> samples{*/
/*{R"!(echo "$(cat /etc/passwd)")!", "cat /etc/passwd"},*/
/*{R"!($(cat /etc/passwd))!", "cat /etc/passwd"},*/
/*{R"!($(echo $(echo $(echo ls))))!", "$(echo $(echo ls))"},*/
/*{R"!($(echo $(echo $(echo ls))))!", "echo ls"},*/
/*{R"!(ls -l $(echo /etc/passwd))!", "-l $(echo /etc/passwd)"},*/
/*{R"!({ ( $(echo ls) ) })!", "echo ls"},*/
/*{R"!({ ( $(echo ls) ) })!", "$(echo ls)"},*/
/*{R"!({ ( $(echo ls) ) })!", "( $(echo ls) )"},*/
/*{R"!({ ( $(echo ls) ) })!", "{ ( $(echo ls) ) }"},*/
/*};*/

/*for (const auto &[resource, param] : samples) {*/
/*ddwaf_object tmp;*/
/*ddwaf_object root;*/

/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(*/
/*&root, "server.sys.shell.cmd", ddwaf_object_string(&tmp, resource.c_str()));*/
/*ddwaf_object_map_add(*/
/*&root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));*/

/*object_store store;*/
/*store.insert(root);*/

/*ddwaf::timer deadline{2s};*/
/*condition_cache cache;*/
/*auto res = cond.eval(cache, store, {}, {}, deadline);*/
/*ASSERT_TRUE(res.outcome) << resource;*/
/*EXPECT_FALSE(res.ephemeral);*/

/*EXPECT_TRUE(cache.match);*/
/*EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");*/
/*EXPECT_STR(cache.match->args[0].resolved, resource.c_str());*/
/*EXPECT_TRUE(cache.match->args[0].key_path.empty());*/

/*EXPECT_STRV(cache.match->args[1].address, "server.request.query");*/
/*EXPECT_STR(cache.match->args[1].resolved, param.c_str());*/
/*EXPECT_TRUE(cache.match->args[1].key_path.empty());*/

/*EXPECT_STR(cache.match->highlights[0], param.c_str());*/
/*}*/
/*}*/

/*TEST(TestShiDetectorArray, InjectionsWithinProcessSubstitution)*/
/*{*/
/*shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};*/

/*std::vector<std::pair<std::string, std::string>> samples{*/
/*{R"!(echo >(ls -l))!", "ls -l"},*/
/*{R"!(diff <(file) <(rm -rf /etc/systemd/))!", "rm -rf /etc/systemd/"},*/
/*};*/

/*for (const auto &[resource, param] : samples) {*/
/*ddwaf_object tmp;*/
/*ddwaf_object root;*/

/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(*/
/*&root, "server.sys.shell.cmd", ddwaf_object_string(&tmp, resource.c_str()));*/
/*ddwaf_object_map_add(*/
/*&root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));*/

/*object_store store;*/
/*store.insert(root);*/

/*ddwaf::timer deadline{2s};*/
/*condition_cache cache;*/
/*auto res = cond.eval(cache, store, {}, {}, deadline);*/
/*ASSERT_TRUE(res.outcome) << resource;*/
/*EXPECT_FALSE(res.ephemeral);*/

/*EXPECT_TRUE(cache.match);*/
/*EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");*/
/*EXPECT_STR(cache.match->args[0].resolved, resource.c_str());*/
/*EXPECT_TRUE(cache.match->args[0].key_path.empty());*/

/*EXPECT_STRV(cache.match->args[1].address, "server.request.query");*/
/*EXPECT_STR(cache.match->args[1].resolved, param.c_str());*/
/*EXPECT_TRUE(cache.match->args[1].key_path.empty());*/

/*EXPECT_STR(cache.match->highlights[0], param.c_str());*/
/*}*/
/*}*/

/*TEST(TestShiDetectorArray, OffByOnePayloadsMatch)*/
/*{*/
/*shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};*/

/*std::vector<std::pair<std::string, std::string>> samples{*/
/*{R"(cat hello> cat /etc/passwd; echo "")", R"(hello>)"},*/
/*{R"(cat hello> cat /etc/passwd; echo "")", R"(t hello)"},*/
/*{R"(cat hello> cat /etc/passwd; echo "")", R"(cat hello)"},*/
/*{R"!(diff <(file) <(rm -rf /etc/systemd/))!", "rm -"},*/
/*};*/

/*for (const auto &[resource, param] : samples) {*/
/*ddwaf_object tmp;*/
/*ddwaf_object root;*/

/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(*/
/*&root, "server.sys.shell.cmd", ddwaf_object_string(&tmp, resource.c_str()));*/
/*ddwaf_object_map_add(*/
/*&root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));*/

/*object_store store;*/
/*store.insert(root);*/

/*ddwaf::timer deadline{2s};*/
/*condition_cache cache;*/
/*auto res = cond.eval(cache, store, {}, {}, deadline);*/
/*ASSERT_TRUE(res.outcome) << resource;*/
/*EXPECT_FALSE(res.ephemeral);*/

/*EXPECT_TRUE(cache.match);*/
/*EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");*/
/*EXPECT_STR(cache.match->args[0].resolved, resource.c_str());*/
/*EXPECT_TRUE(cache.match->args[0].key_path.empty());*/

/*EXPECT_STRV(cache.match->args[1].address, "server.request.query");*/
/*EXPECT_STR(cache.match->args[1].resolved, param.c_str());*/
/*EXPECT_TRUE(cache.match->args[1].key_path.empty());*/

/*EXPECT_STR(cache.match->highlights[0], param.c_str());*/
/*}*/
/*}*/

/*TEST(TestShiDetectorArray, MultipleArgumentsMatch)*/
/*{*/
/*shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};*/

/*std::string params = R"({*/
/*post: {*/
/*blank: "",*/
/*name: "Create",*/
/*other: "hello",*/
/*other2: "hello; ls /etc/passwd",*/
/*other3: "hello\"; cat /etc/passwd; echo \"",*/
/*other4: "\"hello\\\\\"; cat /etc/passwd; echo",*/
/*other5: "1.json 2> /tmp/toto",*/
/*other6: "1.json > /tmp/toto",*/
/*other7: "google.com; ls",*/
/*other8: "google.com; ${a:-ls}",*/
/*other9: "google.com; TOTO=ls ${a:-$TOTO}",*/
/*other10: "google.com; TOTO=ls $TOTO"*/
/*}*/
/*})";*/

/*std::vector<std::string> samples{*/
/*R"(cat hello; ls /etc/passwd)",*/
/*R"(cat "hello"; cat /etc/passwd; echo "")",*/
/*R"(ping -c 1 google.com; ls)",*/
/*R"(cat "hello\\"; cat /etc/passwd; echo ")",*/
/*R"(ls public/1.json 2> /tmp/toto)",*/
/*R"(ls public/1.json > /tmp/toto)",*/
/*R"(ping -c 1 google.com; ${a:-ls})",*/
/*R"(ping -c 1 google.com; TOTO=ls ${a:-$TOTO})",*/
/*R"(ping -c 1 google.com; TOTO=ls $TOTO)",*/

/*};*/

/*for (const auto &resource : samples) {*/
/*ddwaf_object tmp;*/
/*ddwaf_object root;*/

/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(*/
/*&root, "server.sys.shell.cmd", ddwaf_object_string(&tmp, resource.c_str()));*/
/*auto params_obj = yaml_to_object(params);*/
/*ddwaf_object_map_add(&root, "server.request.query", &params_obj);*/

/*object_store store;*/
/*store.insert(root);*/

/*ddwaf::timer deadline{2s};*/
/*condition_cache cache;*/
/*auto res = cond.eval(cache, store, {}, {}, deadline);*/
/*ASSERT_TRUE(res.outcome) << resource;*/
/*EXPECT_FALSE(res.ephemeral);*/

/*EXPECT_TRUE(cache.match);*/
/*EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");*/
/*EXPECT_STR(cache.match->args[0].resolved, resource.c_str());*/
/*EXPECT_TRUE(cache.match->args[0].key_path.empty());*/
/*}*/
/*}*/

} // namespace
