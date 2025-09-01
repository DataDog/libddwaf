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
    std::string address{"server.request.query"};
    std::string highlight{};
    std::vector<std::string> key_path{};
};

void match_path_and_input(const std::vector<std::pair<std::string, ssrf_sample>> &samples,
    bool match = true, const ssrf_opts &opts = {},
    // NOLINT(bugprone-easily-swappable-parameters)
    std::optional<std::vector<std::string>> allowed_schemes = {},
    std::optional<std::vector<std::string>> forbidden_domains = {},
    std::optional<std::vector<std::string_view>> forbidden_ips = {})
{
    ssrf_detector cond{{gen_param_def("server.io.net.url", "server.request.query")}};
    cond.set_opts(opts);

    if (allowed_schemes.has_value()) {
        cond.set_allowed_schemes(std::move(allowed_schemes.value()));
    }

    if (forbidden_domains.has_value()) {
        cond.set_forbidden_domains(std::move(forbidden_domains.value()));
    }

    if (forbidden_ips.has_value()) {
        cond.set_forbidden_ips(forbidden_ips.value());
    }

    for (const auto &[path, sample] : samples) {
        auto root = object_builder::map({{"server.io.net.url", path},
            {"server.request.query", yaml_to_object<owned_object>(sample.yaml)}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        if (match) {
            ASSERT_TRUE(res.outcome) << path;
            EXPECT_EQ(res.scope, evaluation_scope::context);

            EXPECT_TRUE(cache.match);
            if (cache.match) { // Silence linter
                EXPECT_STRV(cache.match->args[0].address, "server.io.net.url");
                EXPECT_STR(cache.match->args[0].resolved, path);
                EXPECT_TRUE(cache.match->args[0].key_path.empty());

                EXPECT_STRV(cache.match->args[1].address, sample.address);
                if (sample.resolved.empty()) {
                    EXPECT_STR(cache.match->args[1].resolved, sample.yaml);
                } else {
                    EXPECT_STR(cache.match->args[1].resolved, sample.resolved);
                }
                if (sample.highlight.empty()) {
                    if (sample.resolved.empty()) {
                        EXPECT_STR(cache.match->highlights[0], sample.yaml);
                    } else {
                        EXPECT_STR(cache.match->highlights[0], sample.resolved);
                    }
                } else {
                    EXPECT_STR(cache.match->highlights[0], sample.highlight);
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

TEST(TestSSRFDetector, MatchCustomScheme)
{
    match_path_and_input(
        {
            {"gopher://blabla.com/path", {.yaml = R"("gopher:")", .resolved = "gopher:"}},
            {"data://blabla.com/path",
                {.yaml = R"(data://blabla.com)", .resolved = "data://blabla.com"}},
        },
        false, {}, {{"gopher", "data"}});

    match_path_and_input(
        {
            {"https://blabla.com/path", {.yaml = R"("https:")", .resolved = "https:"}},
            {"http://blabla.com/path", {.yaml = R"("http:")", .resolved = "http:"}},
            {"ftp://blabla.com/path", {.yaml = R"("ftp:")", .resolved = "ftp:"}},
            {"ftps://blabla.com/path", {.yaml = R"("ftps:")", .resolved = "ftps:"}},
        },
        true, {}, {{"gopher", "data"}});
}

TEST(TestSSRFDetector, MatchHost)
{
    match_path_and_input(
        {
            {"https://internal-website.evil.com/path/to/stuffs?bla=42",
                {.yaml = ".evil.com/path/to/stuffs?"}},
            {"https://internal-website.evil.com:42/path/to/stuffs?bla=42",
                {.yaml = ".evil.com:42/path/to/stuffs?"}},
            {"https://internal-website:4242/path/to/stuffs?bla=42",
                {.yaml = ":4242/path/to/stuffs?"}},
            {"https://blabla.com/path", {.yaml = ".com/path"}},
            {"http://core-goals.evil.com/v1/projects/42/goals?projectId=42&",
                {.yaml = R"({"path":".evil.com/v1/projects/42/goals?"})",
                    .resolved = ".evil.com/v1/projects/42/goals?",
                    .key_path = {"path"}}},
            {"http://2852039166/latest/meta-data/",
                {.yaml = R"({form: { url: "2852039166/latest/meta-data/" }})",
                    .resolved = "2852039166/latest/meta-data/",
                    .key_path = {"form", "url"}}},
        },
        true, ssrf_opts{.authority_inspection = true});

    match_path_and_input(
        {
            {"https://internal-website.evil.com/path/to/stuffs?bla=42",
                {.yaml = ".evil.com/path/to/stuffs?"}},
            {"https://internal-website.evil.com:42/path/to/stuffs?bla=42",
                {.yaml = ".evil.com:42/path/to/stuffs?"}},
            {"https://internal-website:4242/path/to/stuffs?bla=42",
                {.yaml = ":4242/path/to/stuffs?"}},
            {"https://blabla.com/path", {.yaml = ".com/path"}},
            {"http://core-goals.evil.com/v1/projects/42/goals?projectId=42&",
                {.yaml = R"({"path":".evil.com/v1/projects/42/goals?"})",
                    .resolved = ".evil.com/v1/projects/42/goals?",
                    .key_path = {"path"}}},
            {"http://2852039166/latest/meta-data/",
                {.yaml = R"({form: { url: "2852039166/latest/meta-data/" }})",
                    .resolved = "2852039166/latest/meta-data/",
                    .key_path = {"form", "url"}}},
        },
        false, ssrf_opts{.authority_inspection = false});
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

TEST(TestSSRFDetector, MatchCustomDangerousIP)
{
    match_path_and_input(
        {
            {"https://169.254.169.254/somewhere/in/the/app", {.yaml = "169.254.169.254"}},
            {"https://[::ffff:a9fe:a9fe]/path",
                {.yaml = R"("[::ffff:a9fe:a9fe]")", .resolved = "[::ffff:a9fe:a9fe]"}},
            {"https://[::1]/path", {.yaml = R"("[::1]")", .resolved = "[::1]"}},
            {"http://[::ffff:a9fe:a9fe]/latest/meta-data/",
                {.yaml = R"({form: {url: "[::ffff:a9fe:a9fe]"}})",
                    .resolved = "[::ffff:a9fe:a9fe]",
                    .key_path = {"form", "url"}}},
            {"http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/",
                {.yaml = R"({form: {url: "[0:0:0:0:0:ffff:a9fe:a9fe]"}})",
                    .resolved = "[0:0:0:0:0:ffff:a9fe:a9fe]",
                    .key_path = {"form", "url"}}},
        },
        false, {}, std::nullopt, std::nullopt, {{}});

    match_path_and_input(
        {
            {"https://[07e3:0814:4e19:0362:c5e1:e7ae:492a:6cc2]/somewhere/in/the/app",
                {.yaml = R"("[07e3:0814:4e19:0362:c5e1:e7ae:492a:6cc2]")",
                    .resolved = "[07e3:0814:4e19:0362:c5e1:e7ae:492a:6cc2]"}},
            {"https://13.12.52.213/path", {.yaml = R"(13.12.52.213)"}},
        },
        true, {}, std::nullopt, std::nullopt,
        {{"13.12.52.0/16", "07e3:0814:4e19:0362:c5e1:e7ae:492a:6cc2"}});
}

TEST(TestSSRFDetector, MatchDangerousDomain)
{
    match_path_and_input({
        {"https://blabla.burpcollaborator.net/path", {.yaml = "burpcollaborator.net"}},
        {"https://localhost/path", {.yaml = "localhost"}},
        {"https://ifconfig.pro", {.yaml = "ifconfig.pro"}},
    });
}

TEST(TestSSRFDetector, MatchCustomDangerousDomain)
{
    match_path_and_input(
        {
            {"https://blabla.burpcollaborator.net/path", {.yaml = "burpcollaborator.net"}},
            {"https://localhost/path", {.yaml = "localhost"}},
            {"https://ifconfig.pro", {.yaml = "ifconfig.pro"}},
        },
        false, {}, std::nullopt, {{}});

    match_path_and_input(
        {
            {"https://google.com/path", {.yaml = "google.com"}},
            {"https://meta.facebook.com/profile?id=1298301923", {.yaml = "facebook.com"}},
            {"ftps://this.is.example.com", {.yaml = "example.com"}},
        },
        true, {}, std::nullopt, {{"google.com", "facebook.com", "example.com"}});
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
    match_path_and_input(
        {
            {"https://blabla.com/random/../with?param=value", {.yaml = "../with"}},
            {"https://blabla.com/random/with%2fdodgy/characters?param=value",
                {.yaml = "with%2fdodgy"}},
            {"https://blabla.com/random/with%2Fdodgy/characters?param=value",
                {.yaml = "with%2Fdodgy"}},
            {"https://blabla.com/random/with%5cdodgy/characters?param=value",
                {.yaml = "with%5cdodgy"}},
            {"https://blabla.com/random/with%5Cdodgy/characters?param=value",
                {.yaml = "with%5Cdodgy"}},
            {"https://blabla.com/random/..falsestart.something/../with?param=value",
                {.yaml = "..falsestart.something/../with"}},
            {"https://blabla.com/path?name=param&name2=param2", {.yaml = "param&name2=param2"}},
            {"https://blabla.com/path?name=param&name2=param2",
                {.yaml = "name=param&name2=param2"}},
            {"https://blabla.com/path?name=param&auth=43", {.yaml = "param&auth"}},
            {"https://blabla.com/random/path?name=name2&value=/legit",
                {.yaml = "path?name=name2&value="}},
            {"a://b/c/d?e=f&g=h", {.yaml = "d?e=f&g="}},
            {"http://core-goals/v1/projects/42/goals?projectId=42&",
                {.yaml = R"(/v1/projects/42/goals?)"}},
            {"https://internal-website/path/to/stuffs?bla=42", {.yaml = "/path/to/stuffs?"}},
            //{"http://0:8000/composer/send_email?to=orange@chroot.org&url=http://127.0.0.1:6379/%0D%0ASET",
            //{.yaml="http://127.0.0.1:6379/%0D%0ASET"}},
        },
        true, ssrf_opts{.path_inspection = true, .query_inspection = true});

    // Overlapping injections, where the path is only partially injected, will
    // still match when the query is also injected
    match_path_and_input(
        {
            {"https://blabla.com/random/../with?param=value", {.yaml = "../with"}},
            {"https://blabla.com/random/with%2fdodgy/characters?param=value",
                {.yaml = "with%2fdodgy"}},
            {"https://blabla.com/random/with%2Fdodgy/characters?param=value",
                {.yaml = "with%2Fdodgy"}},
            {"https://blabla.com/random/with%5cdodgy/characters?param=value",
                {.yaml = "with%5cdodgy"}},
            {"https://blabla.com/random/with%5Cdodgy/characters?param=value",
                {.yaml = "with%5Cdodgy"}},
            {"https://blabla.com/random/..falsestart.something/../with?param=value",
                {.yaml = "..falsestart.something/../with"}},
        },
        true, ssrf_opts{.path_inspection = true, .query_inspection = false});

    match_path_and_input(
        {
            {"https://blabla.com/path?name=param&name2=param2", {.yaml = "param&name2=param2"}},
            {"https://blabla.com/path?name=param&name2=param2",
                {.yaml = "name=param&name2=param2"}},
            {"https://blabla.com/path?name=param&auth=43", {.yaml = "param&auth"}},
            {"https://blabla.com/random/path?name=name2&value=/legit",
                {.yaml = "path?name=name2&value="}},
            {"a://b/c/d?e=f&g=h", {.yaml = "d?e=f&g="}},
            {"http://core-goals/v1/projects/42/goals?projectId=42&",
                {.yaml = R"(/v1/projects/42/goals?)"}},
            {"https://internal-website/path/to/stuffs?bla=42", {.yaml = "/path/to/stuffs?"}},
        },
        false, ssrf_opts{.path_inspection = true, .query_inspection = false});

    // Validate only query injections
    match_path_and_input(
        {
            {"https://blabla.com/path?name=param&name2=param2", {.yaml = "param&name2=param2"}},
            {"https://blabla.com/path?name=param&name2=param2",
                {.yaml = "name=param&name2=param2"}},
            {"https://blabla.com/path?name=param&auth=43", {.yaml = "param&auth"}},
            {"https://blabla.com/random/path?name=name2&value=/legit",
                {.yaml = "path?name=name2&value="}},
            {"a://b/c/d?e=f&g=h", {.yaml = "d?e=f&g="}},
            {"http://core-goals/v1/projects/42/goals?projectId=42&",
                {.yaml = R"(/v1/projects/42/goals?)"}},
            {"https://internal-website/path/to/stuffs?bla=42", {.yaml = "/path/to/stuffs?"}},
        },
        true, ssrf_opts{.path_inspection = false, .query_inspection = true});

    match_path_and_input(
        {
            {"https://blabla.com/random/../with?param=value", {.yaml = "../with"}},
            {"https://blabla.com/random/with%2fdodgy/characters?param=value",
                {.yaml = "with%2fdodgy"}},
            {"https://blabla.com/random/with%2Fdodgy/characters?param=value",
                {.yaml = "with%2Fdodgy"}},
            {"https://blabla.com/random/with%5cdodgy/characters?param=value",
                {.yaml = "with%5cdodgy"}},
            {"https://blabla.com/random/with%5Cdodgy/characters?param=value",
                {.yaml = "with%5Cdodgy"}},
            {"https://blabla.com/random/..falsestart.something/../with?param=value",
                {.yaml = "..falsestart.something/../with"}},
        },
        false, ssrf_opts{.path_inspection = false, .query_inspection = true});
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

TEST(TestSSRFDetector, EnforcePolicyWithoutInjection)
{
    match_path_and_input(
        {
            // Forbidden IP
            {"https://169.254.169.254/somewhere/in/the/app",
                {.yaml = "", .address = "", .highlight = "https://169.254.169.254"}},
            {"ftp://127.0.0.1/not/found?test=true",
                {.yaml = "", .address = "", .highlight = "ftp://127.0.0.1"}},
            {"ftps://10.25.26.27/", {.yaml = "", .address = "", .highlight = "ftps://10.25.26.27"}},
            {"ftps://172.16.2.3/local",
                {.yaml = "", .address = "", .highlight = "ftps://172.16.2.3"}},
            {"ftps://192.168.2.3/config",
                {.yaml = "", .address = "", .highlight = "ftps://192.168.2.3"}},
            {"ftps://100.64.123.33/etc/passwd",
                {.yaml = "", .address = "", .highlight = "ftps://100.64.123.33"}},
            {"https://[::ffff:a9fe:a9fe]/path",
                {.yaml = "", .address = "", .highlight = "https://[::ffff:a9fe:a9fe]"}},
            {"https://[::1]/path", {.yaml = "", .address = "", .highlight = "https://[::1]"}},
            {"http://[::ffff:a9fe:a9fe]/latest/meta-data/",
                {.yaml = "", .address = "", .highlight = "http://[::ffff:a9fe:a9fe]"}},
            {"http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/",
                {.yaml = "", .address = "", .highlight = "http://[0:0:0:0:0:ffff:a9fe:a9fe]"}},
            // Forbidden Domain
            {"https://blabla.burpcollaborator.net/path",
                {.yaml = "", .address = "", .highlight = "https://blabla.burpcollaborator.net"}},
            {"https://localhost/path",
                {.yaml = "", .address = "", .highlight = "https://localhost"}},
            {"https://server.local",
                {.yaml = "", .address = "", .highlight = "https://server.local"}},
            {"https://server.internal/common",
                {.yaml = "", .address = "", .highlight = "https://server.internal"}},
            {"https://metadata.google/whatever",
                {.yaml = "", .address = "", .highlight = "https://metadata.google"}},
            {"https://ram.aliyuncs.com",
                {.yaml = "", .address = "", .highlight = "https://ram.aliyuncs.com"}},
            {"https://ifconfig.pro",
                {.yaml = "", .address = "", .highlight = "https://ifconfig.pro"}},
            {"https://home.localtest.me",
                {.yaml = "", .address = "", .highlight = "https://home.localtest.me"}},
            {"https://localtest.me",
                {.yaml = "", .address = "", .highlight = "https://localtest.me"}},
            {"http://localhost/", {.yaml = "", .address = "", .highlight = "http://localhost"}},
            // Non-allowed scheme
            {"gopher://example.com/",
                {.yaml = "", .address = "", .highlight = "gopher://example.com"}},
            {"data://google.com/search",
                {.yaml = "", .address = "", .highlight = "data://google.com"}},
        },
        true, ssrf_opts{.enforce_policy_without_injection = true});

    // Counter examples
    match_path_and_input(
        {
            {"https://169.253.169.253/somewhere/in/the/app", {.yaml = ""}},
            {"ftp://127.0.0.2/not/found?test=true", {.yaml = ""}},
            {"http://[0:0:0:0:11:ffff:a9fe:a9fe]/latest/meta-data/", {.yaml = ""}},
            {"https://blabla.burp-non-collaborator.net/path", {.yaml = ""}},
            {"https://server.non-local", {.yaml = ""}},
            {"https://server.external/common", {.yaml = ""}},
            {"https://metadata.something/whatever", {.yaml = ""}},
            {"https://mem.aliyuncs.com", {.yaml = ""}},
            {"https://ifconfig.nonpro", {.yaml = ""}},
            {"https://home.local.me", {.yaml = ""}},
            {"https://localhost.me", {.yaml = ""}},
            {"http://localost/", {.yaml = ""}},
        },
        false, ssrf_opts{.enforce_policy_without_injection = true});

    match_path_and_input(
        {
            // Forbidden IP
            {"https://169.254.169.254/somewhere/in/the/app", {.yaml = ""}},
            {"ftp://127.0.0.1/not/found?test=true", {.yaml = ""}},
            {"ftps://10.25.26.27/", {.yaml = ""}},
            {"ftps://172.16.2.3/local", {.yaml = ""}},
            {"ftps://192.168.2.3/config", {.yaml = ""}},
            {"ftps://100.64.123.33/etc/passwd", {.yaml = ""}},
            {"https://[::ffff:a9fe:a9fe]/path", {.yaml = ""}},
            {"https://[::1]/path", {.yaml = ""}},
            {"http://[::ffff:a9fe:a9fe]/latest/meta-data/", {.yaml = ""}},
            {"http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/", {.yaml = ""}},
            // Forbidden Domain
            {"https://blabla.burpcollaborator.net/path", {.yaml = ""}},
            {"https://localhost/path", {.yaml = ""}},
            {"https://server.local", {.yaml = ""}},
            {"https://server.internal/common", {.yaml = ""}},
            {"https://metadata.google/whatever", {.yaml = ""}},
            {"https://ram.aliyuncs.com", {.yaml = ""}},
            {"https://ifconfig.pro", {.yaml = ""}},
            {"https://home.localhost.me", {.yaml = ""}},
            {"https://localhost.me", {.yaml = ""}},
            {"http://localhost/", {.yaml = ""}},
            // Non-allowed scheme
            {"gopher://example.com/", {.yaml = ""}},
            {"data://google.com/search", {.yaml = ""}},
        },
        false, ssrf_opts{.enforce_policy_without_injection = false});
}

TEST(TestSSRFDetector, ForbidFullUrlInjection)
{
    // Test cases where injected URL is equivalent to reference URL should match
    // when forbid_full_url_injection is true
    match_path_and_input(
        {
            {"https://example.com/path",
                {.yaml = R"("https://example.com/path")", .resolved = "https://example.com/path"}},
            {"http://api.example.com/endpoint", {.yaml = R"("http://api.example.com/endpoint")",
                                                    .resolved = "http://api.example.com/endpoint"}},
            {"https://service.org/data",
                {.yaml = R"("https://service.org/data")", .resolved = "https://service.org/data"}},
            {"http://app.com/service", {.yaml = R"({url: "http://app.com/service"})",
                                           .resolved = "http://app.com/service",
                                           .key_path = {"url"}}},
            {"https://trusted.org/api/v1", {.yaml = R"({redirect: "https://trusted.org/api/v1"})",
                                               .resolved = "https://trusted.org/api/v1",
                                               .key_path = {"redirect"}}},
        },
        true, ssrf_opts{.forbid_full_url_injection = true});

    // Test cases where injected URL is different from reference URL - should NOT match when
    // forbid_full_url_injection is true
    match_path_and_input(
        {
            {"https://example.com/path", {.yaml = R"("https://malicious.com/evil")"}},
            {"http://safe.com/endpoint", {.yaml = R"("http://attacker.com")"}},
            {"https://trusted.org/api", {.yaml = R"("ftp://internal.local/secret")"}},
            {"http://app.example.com/service", {.yaml = R"({url: "https://evil.com/payload"})"}},
            {"https://api.example.com/v1/data",
                {.yaml = R"({redirect: "http://localhost:8080/admin"})"}},
        },
        false, ssrf_opts{.forbid_full_url_injection = true});

    // Test cases where different URLs should match when forbid_full_url_injection is false
    match_path_and_input(
        {
            {"https://example.com/path", {.yaml = R"("https://example.com/path")"}},
            {"http://api.example.com/endpoint", {.yaml = R"("http:api.example.com/endpoint")"}},
            {"https://service.org/data", {.yaml = R"("https://service.org/data")"}},
            {"http://app.com/service", {.yaml = R"({url: "http://app.com/service"})"}},
            {"https://trusted.org/api/v1", {.yaml = R"({redirect:
               "https:trusted.org/api/v1"})"}},
            {"https://example.com/path/../in/somewhere?param=value",
                {.yaml = R"("https://example.com/path/../in/somewhere?param=value")"}},
        },
        false, ssrf_opts{.forbid_full_url_injection = false});
}

} // namespace
