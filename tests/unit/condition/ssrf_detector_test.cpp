// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "condition/ssrf_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
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
        auto root = owned_object::make_map({{"server.io.net.url", path},
            {"server.request.query", yaml_to_object<owned_object>(sample.yaml)}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        if (match) {
            ASSERT_TRUE(res.outcome) << path;
            EXPECT_FALSE(res.ephemeral);

            EXPECT_TRUE(cache.match);
            if (cache.match) { // Silence linter
                EXPECT_STRV(cache.match->args[0].address, "server.io.net.url");
                EXPECT_STR(cache.match->args[0].resolved, path);
                EXPECT_TRUE(cache.match->args[0].key_path.empty());

                EXPECT_STRV(cache.match->args[1].address, "server.request.query");
                if (sample.resolved.empty()) {
                    EXPECT_STR(cache.match->args[1].resolved, sample.yaml);
                    EXPECT_STR(cache.match->highlights[0], sample.yaml);
                } else {
                    EXPECT_STR(cache.match->args[1].resolved, sample.resolved);
                    EXPECT_STR(cache.match->highlights[0], sample.resolved);
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
        {"gopher://blabla.com/path", {.yaml = R"("gopher:")", .resolved = "gopher:"}},
        {"data://blabla.com/path",
            {.yaml = R"(data://blabla.com)", .resolved = "data://blabla.com"}},
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
    match_path_and_input({
        {"https://blabla.com/random/../with?param=value", {.yaml = "../with"}},
        {"https://blabla.com/random/with%2fdodgy/characters?param=value", {.yaml = "with%2fdodgy"}},
        {"https://blabla.com/random/with%2Fdodgy/characters?param=value", {.yaml = "with%2Fdodgy"}},
        {"https://blabla.com/random/with%5cdodgy/characters?param=value", {.yaml = "with%5cdodgy"}},
        {"https://blabla.com/random/with%5Cdodgy/characters?param=value", {.yaml = "with%5Cdodgy"}},
        {"https://blabla.com/random/..falsestart.something/../with?param=value",
            {.yaml = "..falsestart.something/../with"}},
        {"https://blabla.com/path?name=param&name2=param2", {.yaml = "param&name2=param2"}},
        {"https://blabla.com/path?name=param&name2=param2", {.yaml = "name=param&name2=param2"}},
        {"https://blabla.com/path?name=param&auth=43", {.yaml = "param&auth"}},
        {"https://blabla.com/random/path?name=name2&value=/legit",
            {.yaml = "path?name=name2&value="}},
        {"a://b/c/d?e=f&g=h", {.yaml = "d?e=f&g="}},
        {"http://core-goals/v1/projects/42/goals?projectId=42&",
            {.yaml = R"(/v1/projects/42/goals?)"}},
        {"https://internal-website/path/to/stuffs?bla=42", {.yaml = "/path/to/stuffs?"}},
        //{"http://0:8000/composer/send_email?to=orange@chroot.org&url=http://127.0.0.1:6379/%0D%0ASET",
        //{.yaml="http://127.0.0.1:6379/%0D%0ASET"}},
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
            {"http://policies.production.svc.cluster.local/"
             "findTravelPolicies?include[]=rules&where=mongoQuery",
                {.yaml = R"({product: flight})"}},
            {"http://internal-microservices-production-4242.eu-west-1.elb.amazonaws.com/"
             "service-legacy/users/4242/evaluations.json?page=1",
                {.yaml = R"({request: {path: "/users/1519111/evaluations.json?page=1"}})"}},
            {"http://pro.orange.fr/css/fonts/opus-meteo/fonts/opus-meteo.ttf?blablabla",
                {.yaml =
                        R"({query: {base: "https://pro.orange.fr/css/fonts/opus-meteo/style.css", uri: "fonts/opus-meteo.ttf?blablabla"}})"}},
            {"http://threatguard-prod-tg-api.iaas.checkpoint.com/api/v1/lookalike/"
             "screenshotB64?date=2020-01-17&lookalike=base64=",
                {.yaml = R"({query: {lookalike: base64=}})"}},
            {"http://cn-cache.ryzerobotics.com/support/"
             "service-policies?cache=update&cache-gateway=1",
                {.yaml = R"({path: "/support/service-policies?cache=update"})"}},
            {"http://s3.eu-central-1.amazonaws.com/bla/production/p/bla/blablabla.../"
             "BLABLABLA.html",
                {.yaml = R"({path: "/p/bla/blablabla.../BLABLABLA"})"}},
            {"http://blablabla.com/api/v3/ds/data-checks", {.yaml = R"({bla: "ds/data-checks"})"}},
            {"http://blablabla.comhttps://blablabla", {.yaml = R"({bla: https})"}},
            {"http://172.16.87.100:1234/pouet/bla/_search?stuff=87.1",
                {.yaml = R"({stuff: "87.1"})"}},
            {"tax.internal.patreon.com/services/tax/1.0/quote/batch",
                {.yaml = R"({query: {utm_campaign: ["patreon"]}})"}},
            {"http://bla.patreon.com/batch", {.yaml = R"({query: {param: "patreon.com/"}})"}},
            {"http://google.com/batch", {.yaml = R"({query: {param: "batch"}})"}},
            {"http://google.com/batch", {.yaml = R"({query: {param: "/batch"}})"}},
            {"file/blabla/metadata", {.yaml = R"({query: {param: "blabla"}})"}},
            {"gopher://blabla.com/path", {.yaml = "gopher"}},
            {"data://blabla.com/path", {.yaml = "data"}},
            /*            {"http://scrapper-proxy.awsregion.bla.iohttps://images.bla.com/whatever",*/
            /*{.yaml = R"({url: "https://images.bla.com/whatever"})"}},*/
        },
        false);
}

} // namespace
