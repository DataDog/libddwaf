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

TEST(TestSSRFDetector, MatchBasicUnix)
{
    ssrf_detector cond{{gen_param_def("server.io.net.url", "server.request.query")}};

    std::vector<std::pair<std::string, std::string>> samples{
        {"https://169.254.169.254/somewhere/in/the/app", "169.254.169.254"}};

    for (const auto &[path, input] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.io.net.url", ddwaf_object_string(&tmp, path.c_str()));
        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, input.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        EXPECT_TRUE(res.outcome);
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.io.net.url");
        EXPECT_STR(cache.match->args[0].resolved, path.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, input.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], input.c_str());
    }
}

} // namespace
