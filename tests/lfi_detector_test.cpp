// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<parameter_definition> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST(TestLFIDetector, BasicMatches)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {"documents/../../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd"},
        {"../../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd"},
        {"/etc/passwd", "/etc/passwd"},
        {"./../etc/passwd", "../etc/passwd"},
        {"imgs/../secret.yml", "../secret.yml"},
    };

    for (const auto &[path, input] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.io.fs.file", ddwaf_object_string(&tmp, path.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
        EXPECT_STR(cache.match->args[0].resolved, path.c_str());
        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input.c_str());

        EXPECT_STR(cache.match->highlights[0], input.c_str());
    }
}

TEST(TestLFIDetector, NoMatch)
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
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.io.fs.file", ddwaf_object_string(&tmp, path.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_FALSE(res.outcome);
        EXPECT_FALSE(cache.match);
    }
}

} // namespace
