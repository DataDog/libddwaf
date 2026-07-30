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

TEST(TestShiDetectorString, InvalidType)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root = object_builder_da::map(
        {{"server.sys.shell.cmd",
             owned_object{{.type = object_type::invalid}, memory::get_default_resource()}},
            {"server.request.query", "whatever"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
}

TEST(TestShiDetectorString, EmptyResource)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root = object_builder_da::map(
        {{"server.sys.shell.cmd", ""}, {"server.request.query", "whatever"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
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
        auto root = object_builder_da::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_FALSE(cond.eval(cache, store, {}, {}, deadline));
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
        auto root = object_builder_da::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

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
        auto root = object_builder_da::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

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
        auto root = object_builder_da::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

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
        auto root = object_builder_da::map({
            {"server.sys.shell.cmd", resource},
            {"server.request.query", param},
        });

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

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
        auto root = object_builder_da::map({{"server.sys.shell.cmd", resource},
            {"server.request.query", yaml_to_object<owned_object>(params)}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());
    }
}

// Generates the parameter definition of a two-argument detector, applying the
// given transformers to the second (params) argument only
std::vector<condition_parameter> gen_param_def_with_transformers(
    std::string_view resource, std::string_view params, std::vector<transformer_id> transformers)
{
    return {condition_parameter{{condition_target{
                .name = std::string{resource}, .index = get_target_index(resource)}}},
        condition_parameter{{condition_target{.name = std::string{params},
            .index = get_target_index(params),
            .key_path = {},
            .transformers = std::move(transformers)}}}};
}

TEST(TestShiDetectorString, NoMatchWithoutTransformer)
{
    shi_detector cond{{gen_param_def("server.sys.shell.cmd", "server.request.query")}};

    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls -l; cat /etc/passwd"},
        {"server.request.query", "%3B%20cat%20%2Fetc%2Fpasswd"},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

TEST(TestShiDetectorString, MatchWithTransformer)
{
    shi_detector cond{gen_param_def_with_transformers(
        "server.sys.shell.cmd", "server.request.query", {transformer_id::url_decode})};

    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls -l; cat /etc/passwd"},
        {"server.request.query", "%3B%20cat%20%2Fetc%2Fpasswd"},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.sys.shell.cmd");
    EXPECT_STR(cache.match->args[0].resolved, "ls -l; cat /etc/passwd");

    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    // The reported parameter is the transformed one
    EXPECT_STR(cache.match->args[1].resolved, "; cat /etc/passwd");
    EXPECT_STR(cache.match->highlights[0], "; cat /etc/passwd");
}

TEST(TestShiDetectorString, MatchWithMultipleTransformers)
{
    shi_detector cond{gen_param_def_with_transformers("server.sys.shell.cmd",
        "server.request.query", {transformer_id::base64_decode, transformer_id::url_decode})};

    // base64("%3B%20cat%20%2Fetc%2Fpasswd")
    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls -l; cat /etc/passwd"},
        {"server.request.query", "JTNCJTIwY2F0JTIwJTJGZXRjJTJGcGFzc3dk"},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], "; cat /etc/passwd");
}

// When the transformers leave the parameter untouched, the original value must
// still be evaluated
TEST(TestShiDetectorString, MatchWithUnappliedTransformer)
{
    shi_detector cond{gen_param_def_with_transformers(
        "server.sys.shell.cmd", "server.request.query", {transformer_id::url_decode})};

    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls -l; cat /etc/passwd"},
        {"server.request.query", "; cat /etc/passwd"},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], "; cat /etc/passwd");
}

// Every parameter within the container must be transformed independently
TEST(TestShiDetectorString, MatchWithTransformerWithinContainer)
{
    shi_detector cond{gen_param_def_with_transformers(
        "server.sys.shell.cmd", "server.request.query", {transformer_id::url_decode})};

    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls -l; cat /etc/passwd"},
        {"server.request.query", object_builder_da::map({{"harmless", "not an injection"},
                                     {"payload", "%3B%20cat%20%2Fetc%2Fpasswd"}})},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], "; cat /etc/passwd");
    ASSERT_EQ(cache.match->args[1].key_path.size(), 1);
    EXPECT_STR(std::get<std::string_view>(cache.match->args[1].key_path[0]), "payload");
}

// The resource is never transformed, only the parameters
TEST(TestShiDetectorString, ResourceNotTransformed)
{
    shi_detector cond{{condition_parameter{{condition_target{.name = "server.sys.shell.cmd",
                           .index = get_target_index("server.sys.shell.cmd"),
                           .key_path = {},
                           .transformers = {transformer_id::url_decode}}}},
        condition_parameter{{condition_target{
            .name = "server.request.query", .index = get_target_index("server.request.query")}}}}};

    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls%20-l%3B%20cat%20%2Fetc%2Fpasswd"},
        {"server.request.query", "; cat /etc/passwd"},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

// A parameter which is reduced to an empty string by the transformers must not
// be considered an injection, as an empty parameter would otherwise be found at
// every position of the resource
TEST(TestShiDetectorString, NoMatchOnEmptyTransformedParameter)
{
    shi_detector cond{gen_param_def_with_transformers(
        "server.sys.shell.cmd", "server.request.query", {transformer_id::remove_nulls})};

    const std::string nulls("\0\0\0", 3);
    auto root = object_builder_da::map({
        {"server.sys.shell.cmd", "ls"},
        {"server.request.query", nulls},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

} // namespace
