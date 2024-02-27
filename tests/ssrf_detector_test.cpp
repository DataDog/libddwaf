// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/ssrf_detector.hpp"
#include "platform.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<parameter_definition> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

struct ssrf_sample {
    std::string yaml;
    std::string resolved{};
    std::vector<std::string> key_path{};
};

void match_path_and_input(
    const std::vector<std::pair<std::string, ssrf_sample>> &samples, bool match = true)
{
    ssrf_detector cond{{gen_param_def("server.io.net.url", "server.request.query")}};

    for (const auto &[path, sample] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.io.net.url", ddwaf_object_string(&tmp, path.c_str()));

        auto input = yaml_to_object(sample.yaml);
        ddwaf_object_map_add(&root, "server.request.query", &input);

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        if (match) {
            ASSERT_TRUE(res.outcome) << path;
            EXPECT_FALSE(res.ephemeral);

            EXPECT_TRUE(cache.match);
            if (cache.match) { // Silence linter
                EXPECT_STRV(cache.match->args[0].address, "server.io.net.url");
                EXPECT_STR(cache.match->args[0].resolved, path.c_str());
                EXPECT_TRUE(cache.match->args[0].key_path.empty());

                EXPECT_STRV(cache.match->args[1].address, "server.request.query");
                if (sample.resolved.empty()) {
                    EXPECT_STR(cache.match->args[1].resolved, sample.yaml.c_str());
                    EXPECT_STR(cache.match->highlights[0], sample.yaml.c_str());
                } else {
                    EXPECT_STR(cache.match->args[1].resolved, sample.resolved.c_str());
                    EXPECT_STR(cache.match->highlights[0], sample.resolved.c_str());
                }
                EXPECT_TRUE(cache.match->args[1].key_path == sample.key_path) << path;
            }
        } else {
            EXPECT_FALSE(res.outcome) << path;
            EXPECT_FALSE(cache.match);
        }
    }
}

TEST(TestSSRFDetector, MatchScheme)
{
    match_path_and_input({
        {"gopher://blabla.com/path", {.yaml = "gopher"}},
    });
}

TEST(TestSSRFDetector, MatchHost)
{
    match_path_and_input({
        {"https://internal-website.evil.com/path/to/stuffs?bla=42",
            {.yaml = ".evil.com/path/to/stuffs?"}},
        {"https://internal-website.evil.com:42/path/to/stuffs?bla=42",
            {.yaml = ".evil.com:42/path/to/stuffs?"}},
        {"https://internal-website:4242/path/to/stuffs?bla=42", {.yaml = ":4242/path/to/stuffs?"}},
        {"https://blabla.com/path", {.yaml = ".com/path"}},
        {"http://core-goals.evil.com/v1/projects/42/goals?projectId=42&",
            {.yaml = R"({"path":".evil.com/v1/projects/42/goals?"})",
                .resolved = ".evil.com/v1/projects/42/goals?",
                .key_path = {"path"}}},
        {"http://2852039166/latest/meta-data/",
            {.yaml = R"({form: { url: "2852039166/latest/meta-data/" }})",
                .resolved = "2852039166/latest/meta-data/",
                .key_path = {"form", "url"}}},
    });
}
TEST(TestSSRFDetector, MatchDangerousIP)
{
    match_path_and_input({
        {"https://169.254.169.254/somewhere/in/the/app", {.yaml = "169.254.169.254"}},
        {"https://[::ffff:a9fe:a9fe]/path",
            {.yaml = R"("[::ffff:a9fe:a9fe]")", .resolved = "[::ffff:a9fe:a9fe]"}},
        {"https://[::1]/path", {.yaml = R"("[::1]")", .resolved = "[::1]"}},
        {"http://[::ffff:a9fe:a9fe]/latest/meta-data/",
            {.yaml = R"({form: {url: "[::ffff:a9fe:a9fe]/latest/meta-data/"}})",
                .resolved = "[::ffff:a9fe:a9fe]/latest/meta-data/",
                .key_path = {"form", "url"}}},
        {"http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/",
            {.yaml = R"({form: {url: "[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/"}})",
                .resolved = "[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/",
                .key_path = {"form", "url"}}},
        //{"https://127.1/path", "127.1"} // TODO: not parsed by inet_pton
    });
}

TEST(TestSSRFDetector, MatchDangerousDomain)
{
    match_path_and_input({
        {"https://blabla.burpcollaborator.net/path", {.yaml = "burpcollaborator.net"}},
        {"https://localhost/path", {.yaml = "localhost"}},
        {"https://ifconfig.pro", {.yaml = "ifconfig.pro"}},
    });
}

TEST(TestSSRFDetector, NoMatch)
{
    match_path_and_input(
        {
            {"https://metadata.google/private_keys/", {.yaml = "{trap: metadata}"}},
            {"https://254.254.169.254/path", {.yaml = "{form: {bla: '254.254.169.254'}}"}},
            {"https://[::ffff:fea9:a9fe]/path", {.yaml = "{form: {bla: '[::ffff:fea9:a9fe]'}}"}},
            {"https://internal-website/path/to/stuffs?bla=42", {.yaml = "/path/to/stuffs?"}},
            {"https://blabla.com/random/path?name=/name2", {.yaml = "{form: {bla: '/name2'}}"}},
            {"https://blabla.com/random/path?name=name2#bla/name2",
                {.yaml = "{form: {bla: '/name2'}}"}},
            {"https://blabla.com/random/path#/name2", {.yaml = "{form: {bla: '#/name2'}}"}},
            {"https://blabla.com/random/path/with?param=val",
                {.yaml = "{form: {bla: '/random/path/with?param=val'}}"}},
            {"https://blabla.com/random/path/with?param=val",
                {.yaml = "{form: {bla: 'random/path/with?param=val'}}"}},
            {"https://123.123.123.123/blablabla", {.yaml = "{form: '123.123.123.123'}"}},
        },
        false);
}

TEST(TestSSRFDetector, MatchParameterInjection)
{
    match_path_and_input({{"https://blabla.com/random/../with?param=value", {.yaml = "../with"}},
        {"https://blabla.com/random/..falsestart.something/../with?param=value",
            {.yaml = "..falsestart.something/../with"}},
        {"https://blabla.com/path?name=param&name2=param2", {.yaml = "param&name2=param2"}},
        {"https://blabla.com/path?name=param&auth=43", {.yaml = "param&auth"}},
        {"https://blabla.com/random/path?name=name2&lol=/legit", {.yaml = "path?name=name2&lol="}}

    });
}

TEST(TestSSRFDetector, NoMatchPotentialFalsePositives)
{
    match_path_and_input(
        {
            {"https://graph.microsoft.com/v1.0/me/calendars/base64stuff=/events/base64stuff2='",
                {.yaml = R"({form: {calendarId: "base64stuff="}})"}},
            {"https://graph.microsoft.com/v1.0/me/calendars/base64stuff=/events",
                {.yaml = R"({form: {calendarId: "base64stuff="}})"}},
            {"https://s3-us-west-2.amazonaws.com/xxx-hosted-content/iframe_pages/424242/path/"
             "to_file.mp3",
                {.yaml = R"({form: {path: "path/to_file.mp3"}})"}},

            // TODO: fix this case
            //{"http://scrapper-proxy.awsregion.bla.iohttps//images.bla.com/whatever", {.yaml =
            //R"({url: "https//images.bla.com/whatever"})"}},
        },
        false);
}

} // namespace
