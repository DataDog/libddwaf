// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "builder/waf_builder.hpp"
#include "common/gtest_utils.hpp"
#include "waf.hpp"

using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "unit";

ddwaf::waf build_instance(std::string_view rule_file)
{
    auto object = read_file(rule_file, base_dir);
    if (object.type == DDWAF_OBJ_INVALID) {
        throw std::runtime_error("Invalid ruleset object");
    }

    raw_configuration ruleset = object;
    waf_builder builder{ddwaf_object_free, std::make_shared<obfuscator>()};
    ddwaf::null_ruleset_info info;
    auto res = builder.add_or_update("default", ruleset, info);
    ddwaf_object_free(&object);

    if (!res) {
        throw std::runtime_error("Failed to load ruleset");
    }

    return builder.build();
}

TEST(TestWaf, RootAddresses)
{
    auto instance = build_instance("interface.yaml");

    std::set<std::string_view> available_addresses{"value1", "value2"};
    for (const auto *address : instance.get_root_addresses()) {
        EXPECT_NE(available_addresses.find(address), available_addresses.end());
    }
}

TEST(TestWaf, BasicContextRun)
{
    auto instance = build_instance("interface.yaml");

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

    auto *ctx = instance.create_context();
    EXPECT_EQ(ctx->run(root, std::nullopt, std::nullopt, LONG_TIME), DDWAF_MATCH);
    delete ctx;
}

TEST(TestWaf, AddressUniqueness)
{
    std::array<std::string_view, 36> addresses{"grpc.server.method", "grpc.server.request.message",
        "grpc.server.request.metadata", "grpc.server.response.message",
        "grpc.server.response.metadata.headers", "grpc.server.response.metadata.trailers",
        "grpc.server.response.status", "graphql.server.all_resolvers", "graphql.server.resolver",
        "http.client_ip", "server.request.body", "server.request.headers.no_cookies",
        "server.request.path_params", "server.request.query", "server.request.uri.raw",
        "server.request.trailers", "server.request.cookies", "server.response.body",
        "server.response.headers.no_cookies", "server.response.status", "usr.id", "usr.session_id",
        "waf.context.processor", "waf.context.event", "_dd.appsec.fp.http.endpoint",
        "_dd.appsec.fp.http.header", "_dd.appsec.fp.http.network",
        "_dd.appsec.fp.session"
        "_dd.appsec.s.req.body",
        "_dd.appsec.s.req.cookies", "_dd.appsec.s.req.query", "_dd.appsec.s.req.params",
        "_dd.appsec.s.res.body", "_dd.appsec.s.graphql.all_resolvers",
        "_dd.appsec.s.graphql.resolver", "_dd.appsec.s.req.headers", "_dd.appsec.s.res.headers"};

    std::unordered_set<std::size_t> indices;
    for (auto addr : addresses) {
        std::size_t hash = std::hash<std::string_view>()(addr);
        EXPECT_EQ(indices.find(hash), indices.end());
        indices.insert(hash);
    }
}

} // namespace
