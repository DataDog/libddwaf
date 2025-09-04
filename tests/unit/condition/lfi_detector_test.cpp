// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "platform.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST(TestLFIDetector, MatchBasicUnix)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {"documents/../../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd"},
        {"../../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd"},
        {"/etc/passwd", "/etc/passwd"},
        {"./../etc/passwd", "../etc/passwd"},
        {"imgs/../secret.yml", "../secret.yml"},
        {"/safe/dir/../../secret.yml", "../../secret.yml"},
    };

    for (const auto &[path, input] : samples) {
        auto root =
            object_builder::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
        EXPECT_STR(cache.match->args[0].resolved, path);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST(TestLFIDetector, MatchBasicWindows)
{
    system_platform_override spo{platform::windows};

    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {"documents/../../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd"},
        {"../../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd"},
        {"/etc/passwd", "/etc/passwd"},
        {"./../etc/passwd", "../etc/passwd"},
        {"imgs/../secret.yml", "../secret.yml"},
        {"/safe/dir/../../secret.yml", "../../secret.yml"},
        {R"(C:/safe/dir/../../secret.yml)", R"(../../secret.yml)"},
        {R"(C:/safe/dir/../../secret.yml)", R"(C:/safe/dir/../../secret.yml)"},
        {R"(E:/)", R"(E:/)"},
        {R"(documents\..\..\..\..\..\..\..\..\..\etc\passwd)",
            R"(..\..\..\..\..\..\..\..\..\etc\passwd)"},
        {R"(..\..\..\..\..\..\..\..\..\etc\passwd)", R"(..\..\..\..\..\..\..\..\..\etc\passwd)"},
        {R"(\etc\passwd)", R"(\etc\passwd)"},
        {R"(.\..\etc\passwd)", R"(..\etc\passwd)"},
        {R"(imgs\..\secret.yml)", R"(..\secret.yml)"},
        {R"(\safe\dir\..\..\secret.yml)", R"(..\..\secret.yml)"},
        {R"(C:\safe\dir\..\..\secret.yml)", R"(..\..\secret.yml)"},
        {R"(C:\safe\dir\..\..\secret.yml)", R"(C:\safe\dir\..\..\secret.yml)"},
        {R"(E:\)", R"(E:\)"},
        {R"(documents/..\..\..\..\../..\..\../../etc\passwd)",
            R"(..\..\..\..\../..\..\../../etc\passwd)"},
        {R"(..\..\..\../..\..\..\..\..\etc\passwd)", R"(..\..\..\../..\..\..\..\..\etc\passwd)"},
        {R"(\etc/passwd)", R"(\etc/passwd)"},
        {R"(.\../etc\passwd)", R"(../etc\passwd)"},
        {R"(imgs\../secret.yml)", R"(../secret.yml)"},
        {R"(/safe\dir\../../secret.yml)", R"(../../secret.yml)"},
        {R"(C:/safe\dir\..\..\secret.yml)", R"(..\..\secret.yml)"},
        {R"(C:/safe/dir/..\..\secret.yml)", R"(C:/safe/dir/..\..\secret.yml)"},
    };

    for (const auto &[path, input] : samples) {
        auto root =
            object_builder::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome) << path;
        EXPECT_TRUE(res.scope.is_context());

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
        EXPECT_STR(cache.match->args[0].resolved, path);
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input);
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input);
    }
}

TEST(TestLFIDetector, MatchWithKeyPath)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = yaml_to_object<owned_object>(
        R"({server.io.fs.file: documents/../etc/passwd,
        server.request.query: {array: [ {map: ../etc/passwd}]}})");

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());

    EXPECT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
    EXPECT_STR(cache.match->args[0].resolved, "documents/../etc/passwd");
    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    EXPECT_STR(cache.match->args[1].resolved, "../etc/passwd");

    std::vector<std::string> kp{"array", "0", "map"};
    EXPECT_EQ(cache.match->args[1].key_path, kp);

    EXPECT_STR(cache.match->highlights[0], "../etc/passwd");
}

TEST(TestLFIDetector, PartiallySubcontextMatch)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    object_store store;

    {
        auto root =
            object_builder::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"}});
        store.insert(std::move(root));
    }

    {
        auto root = object_builder::map({{"server.request.query", "../../../etc/passwd"}});
        store.insert(std::move(root), evaluation_scope::subcontext());
    }

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_subcontext());

    EXPECT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
    EXPECT_STR(cache.match->args[0].resolved, "/var/www/html/../../../etc/passwd");
    EXPECT_TRUE(cache.match->args[0].key_path.empty());

    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    EXPECT_STR(cache.match->args[1].resolved, "../../../etc/passwd");
    EXPECT_TRUE(cache.match->args[1].key_path.empty());

    EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
}

TEST(TestLFIDetector, SubcontextMatch)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    object_store store;

    auto root = object_builder::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", "../../../etc/passwd"}});

    store.insert(std::move(root), evaluation_scope::subcontext());

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);
    EXPECT_TRUE(res.scope.is_subcontext());

    EXPECT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
    EXPECT_STR(cache.match->args[0].resolved, "/var/www/html/../../../etc/passwd");
    EXPECT_TRUE(cache.match->args[0].key_path.empty());

    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    EXPECT_STR(cache.match->args[1].resolved, "../../../etc/passwd");
    EXPECT_TRUE(cache.match->args[1].key_path.empty());

    EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
}

TEST(TestLFIDetector, NoMatchUnix)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {"documents/../../../../../../../../../etc/passwd", "etc/passwd"},
        {"/home/my/documents/pony.txt", "/home/my/documents/"},
        {"a/etc/password", "a/etc/password"},
        {"documents/pony.txt", "my/documents/pony.txt"},
        {"XXX/YYY/documents/pony.txt", "documents/pony.txt"},
        {"documents/unicorn", "pony.txt"},
        {"documents/unicorn.jp", "pony.jp"},
    };

    for (const auto &[path, input] : samples) {
        auto root =
            object_builder::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome) << path;
        EXPECT_TRUE(res.scope.is_context()) << path;
        EXPECT_FALSE(cache.match);
    }
}

TEST(TestLFIDetector, NoMatchWindows)
{
    system_platform_override spo{platform::windows};

    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {R"(documents\..\..\..\..\..\..\..\..\..\etc\passwd)", R"(etc\passwd)"},
        {R"(\home\my\documents\pony.txt)", R"(\home\my\documents\)"},
        {R"(a\etc\password)", R"(a\etc\password)"},
        {R"(documents\pony.txt)", R"(my\documents\pony.txt)"},
        {R"(XXX\YYY\documents\pony.txt)", R"(documents\pony.txt)"},
        {R"(C:\XXX\YYY\documents\pony.txt)", R"(documents\pony.txt)"},
        {R"(C:\XXX\YYY\documents\pony.txt)", R"(documents/../pony.txt)"},
        {R"(C:\XXX\YYY\documents\pony.txt)", R"(documents\..\pony.txt)"},
        {R"(C:\XXX\YYY\documents\pony.txt)", R"(C:\YYY\XXX\file.txt)"},
        {R"(documents\unicorn)", R"(pony.txt)"},
        {R"(documents\unicorn.jp)", R"(pony.jp)"},
        {R"(C:\documents\unicorn.jp)", R"(pony.jp)"},
        {R"(C:)", R"(file.json)"},
        {R"(C:\)", R"(file.json)"},
    };

    for (const auto &[path, input] : samples) {
        auto root =
            object_builder::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome) << path;
        EXPECT_TRUE(res.scope.is_context()) << path;
        EXPECT_FALSE(cache.match);
    }
}

TEST(TestLFIDetector, NoMatchExcludedPath)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder::map({
        {"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
    });
    auto params_map = root.emplace(
        "server.request.query", object_builder::map({{"endpoint", "../../../etc/passwd"}}));

    std::unordered_set<object_view> context{params_map.at(0)};
    exclusion::object_set_ref exclusion{.context = context, .subcontext = {}};

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, exclusion, {}, deadline);
    EXPECT_FALSE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, NoMatchExcludedAddress)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", object_builder::map({{"endpoint", "../../../etc/passwd"}})}});

    std::unordered_set<object_view> context{root.at(1)};
    exclusion::object_set_ref exclusion{.context = context, .subcontext = {}};

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, exclusion, {}, deadline);
    EXPECT_FALSE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, Timeout)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", object_builder::map({{"endpoint", "../../../etc/passwd"}})}});

    std::unordered_set<object_view> context{root.at(1)};
    exclusion::object_set_ref exclusion{.context = context, .subcontext = {}};

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    auto res = cond.eval(cache, store, exclusion, {}, deadline);
    EXPECT_FALSE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, NoParams)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder::map({
        {"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
    });

    exclusion::object_set_ref exclusion{.context = {}, .subcontext = {}};

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    auto res = cond.eval(cache, store, exclusion, {}, deadline);
    EXPECT_FALSE(res.outcome);
    EXPECT_TRUE(res.scope.is_context());
    EXPECT_FALSE(cache.match);
}

} // namespace
