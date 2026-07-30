// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "platform.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
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
            object_builder_da::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        EXPECT_TRUE(cond.eval(cache, store, {}, {}, deadline));

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
            object_builder_da::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        EXPECT_TRUE(cond.eval(cache, store, {}, {}, deadline));

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
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    EXPECT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
    EXPECT_STR(cache.match->args[0].resolved, "documents/../etc/passwd");
    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    EXPECT_STR(cache.match->args[1].resolved, "../etc/passwd");

    std::vector<std::variant<std::string_view, int64_t>> kp{"array", 0, "map"};
    EXPECT_EQ(cache.match->args[1].key_path, kp);

    EXPECT_STR(cache.match->highlights[0], "../etc/passwd");
}

TEST(TestLFIDetector, PartialSubcontextMatch)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    object_store ctx_store;
    {
        auto root =
            object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"}});
        ctx_store.insert_and_apply(std::move(root));
    }

    auto sctx_store = object_store::from_upstream_store(ctx_store);
    {
        auto root = object_builder_da::map({{"server.request.query", "../../../etc/passwd"}});
        sctx_store.insert_and_apply(std::move(root));
    }

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_TRUE(cond.eval(cache, sctx_store, {}, {}, deadline));

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
            object_builder_da::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
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
            object_builder_da::map({{"server.io.fs.file", path}, {"server.request.query", input}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
        EXPECT_FALSE(cache.match);
    }
}

TEST(TestLFIDetector, NoMatchExcludedPath)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder_da::map({
        {"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
    });
    auto params_map = root.emplace(
        "server.request.query", object_builder_da::map({{"endpoint", "../../../etc/passwd"}}));

    std::unordered_set<object_cache_key> exclusion{params_map.at(0)};

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, exclusion, {}, deadline));
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, NoMatchExcludedAddress)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", object_builder_da::map({{"endpoint", "../../../etc/passwd"}})}});

    std::unordered_set<object_cache_key> exclusion{root.at(1)};

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, exclusion, {}, deadline));
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, Timeout)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", object_builder_da::map({{"endpoint", "../../../etc/passwd"}})}});

    std::unordered_set<object_cache_key> exclusion{root.at(1)};

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, exclusion, {}, deadline));
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, NoParams)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder_da::map({
        {"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
    });

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
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

TEST(TestLFIDetector, NoMatchWithoutTransformer)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", "..%2F..%2F..%2Fetc%2Fpasswd"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

TEST(TestLFIDetector, MatchWithTransformer)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::url_decode})};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", "..%2F..%2F..%2Fetc%2Fpasswd"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
    EXPECT_STR(cache.match->args[0].resolved, "/var/www/html/../../../etc/passwd");

    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    // The reported parameter is the transformed one
    EXPECT_STR(cache.match->args[1].resolved, "../../../etc/passwd");
    EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
}

TEST(TestLFIDetector, MatchWithMultipleTransformers)
{
    lfi_detector cond{gen_param_def_with_transformers("server.io.fs.file", "server.request.query",
        {transformer_id::base64_decode, transformer_id::url_decode})};

    // base64("..%2F..%2F..%2Fetc%2Fpasswd")
    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", "Li4lMkYuLiUyRi4uJTJGZXRjJTJGcGFzc3dk"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
}

// When the transformers leave the parameter untouched, the original value must
// still be evaluated
TEST(TestLFIDetector, MatchWithUnappliedTransformer)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::url_decode})};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", "../../../etc/passwd"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

    ASSERT_TRUE(cache.match);
    EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
}

// Transformers are applied to each parameter within the container, including keys
TEST(TestLFIDetector, MatchWithTransformerWithinContainer)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::url_decode})};

    {
        auto root =
            object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
                {"server.request.query",
                    object_builder_da::map({{"file", "..%2F..%2F..%2Fetc%2Fpasswd"}})}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        ASSERT_TRUE(cache.match);
        EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
        ASSERT_EQ(cache.match->args[1].key_path.size(), 1);
        EXPECT_STR(std::get<std::string_view>(cache.match->args[1].key_path[0]), "file");
    }

    {
        auto root =
            object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
                {"server.request.query",
                    object_builder_da::map({{"..%2F..%2F..%2Fetc%2Fpasswd", "value"}})}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        ASSERT_TRUE(cache.match);
        EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
    }
}

// Transformers are per-target, so a parameter without transformers must not be
// transformed
TEST(TestLFIDetector, TransformersArePerTarget)
{
    lfi_detector cond{{condition_parameter{{condition_target{
                           .name = "server.io.fs.file",
                           .index = get_target_index("server.io.fs.file"),
                       }}},
        condition_parameter{{condition_target{.name = "server.request.query",
                                 .index = get_target_index("server.request.query"),
                                 .key_path = {},
                                 .transformers = {transformer_id::url_decode}},
            condition_target{.name = "server.request.body",
                .index = get_target_index("server.request.body")}}}}};

    {
        auto root =
            object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
                {"server.request.query", "..%2F..%2F..%2Fetc%2Fpasswd"},
                {"server.request.body", "..%2F..%2F..%2Fetc%2Fpasswd"}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        ASSERT_TRUE(cond.eval(cache, store, {}, {}, deadline));

        ASSERT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->highlights[0], "../../../etc/passwd");
    }

    {
        // Only the body contains the encoded payload, which isn't transformed
        auto root =
            object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
                {"server.request.body", "..%2F..%2F..%2Fetc%2Fpasswd"}});

        object_store store;
        store.insert_and_apply(std::move(root));

        ddwaf::timer deadline{2s};
        condition_cache cache;
        EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
        EXPECT_FALSE(cache.match);
    }
}

// The resource is never transformed, only the parameters
TEST(TestLFIDetector, ResourceNotTransformed)
{
    lfi_detector cond{{condition_parameter{{condition_target{.name = "server.io.fs.file",
                           .index = get_target_index("server.io.fs.file"),
                           .key_path = {},
                           .transformers = {transformer_id::url_decode}}}},
        condition_parameter{{condition_target{
            .name = "server.request.query", .index = get_target_index("server.request.query")}}}}};

    auto root =
        object_builder_da::map({{"server.io.fs.file", "%2Fvar%2Fwww%2F..%2F..%2Fetc%2Fpasswd"},
            {"server.request.query", "../../etc/passwd"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

// The transformed parameter replaces the original one, so a payload which is
// present verbatim within the path is no longer detected once the transformers
// modify it
TEST(TestLFIDetector, NoMatchOnUntransformedParameter)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::lowercase})};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/PASSWD"},
        {"server.request.query", "../../../etc/PASSWD"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

// A parameter reduced to an empty string by the transformers must not be
// considered an exploit
TEST(TestLFIDetector, NoMatchOnEmptyTransformedParameter)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::remove_nulls})};

    const std::string nulls("\0\0\0\0", 4);
    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", nulls}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline));
    EXPECT_FALSE(cache.match);
}

// Parameters which can't be transformed are skipped within the iterator, so the
// deadline must be honoured even when the container holds no strings at all
TEST(TestLFIDetector, TimeoutWithNonStringParams)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::url_decode})};

    auto root = object_builder_da::map();
    root.emplace("server.io.fs.file", "/var/www/html/../../../etc/passwd");
    auto array = root.emplace("server.request.query", object_builder_da::array());
    for (unsigned i = 0; i < 1024; ++i) { array.emplace_back(owned_object::make_signed(i)); }

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{0s};
    condition_cache cache;
    EXPECT_THROW(cond.eval(cache, store, {}, {}, deadline), ddwaf::timeout_exception);
}

// A parameter reduced to an empty string by the transformers must not abort the
// evaluation; remove_comments leaves a cow_string with no underlying buffer
TEST(TestLFIDetector, CommentOnlyTransformedParameter)
{
    lfi_detector cond{gen_param_def_with_transformers(
        "server.io.fs.file", "server.request.query", {transformer_id::remove_comments})};

    auto root = object_builder_da::map({{"server.io.fs.file", "/var/www/html/../../../etc/passwd"},
        {"server.request.query", "#"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    EXPECT_NO_THROW(EXPECT_FALSE(cond.eval(cache, store, {}, {}, deadline)));
    EXPECT_FALSE(cache.match);
}

} // namespace
