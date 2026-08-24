// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/conditions/rasp_transformers";

ddwaf_handle init_waf(std::string_view filename)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>(filename, base_dir);
    if (rule.type == DDWAF_OBJ_INVALID) {
        return nullptr;
    }

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    return handle;
}

// Builds a map with the given string entries
void set_string_map(ddwaf_object *map,
    const std::vector<std::pair<std::string_view, std::string_view>> &entries,
    ddwaf_allocator alloc)
{
    ddwaf_object_set_map(map, entries.size(), alloc);
    for (const auto &[key, value] : entries) {
        ddwaf_object_set_string(ddwaf_object_insert_key(map, key.data(), key.size(), alloc),
            value.data(), value.size(), alloc);
    }
}

TEST(TestRaspTransformersIntegration, LfiMatchWithTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.io.fs.file"), alloc),
        STRL("/var/www/html/../../../etc/passwd"), alloc);
    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        {{"file", "..%2F..%2F..%2Fetc%2Fpasswd"}}, alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(
        out, {.id = "rasp-lfi",
                 .name = "LFI Exploit detection",
                 .tags = {{"type", "lfi"}, {"category", "exploit_detection"}, {"module", "rasp"}},
                 .matches = {{.op = "lfi_detector",
                     .highlight = "../../../etc/passwd"sv,
                     .args = {{.name = "resource",
                                  .value = "/var/www/html/../../../etc/passwd"sv,
                                  .address = "server.io.fs.file"},
                         {.name = "params",
                             .value = "../../../etc/passwd"sv,
                             .address = "server.request.query",
                             .path = {"file"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

// The same payload on an address without transformers must not match
TEST(TestRaspTransformersIntegration, LfiNoMatchWithoutTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.io.fs.file"), alloc),
        STRL("/var/www/html/../../../etc/passwd"), alloc);
    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.body"), alloc),
        {{"file", "..%2F..%2F..%2Fetc%2Fpasswd"}}, alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

// A payload which doesn't require transformation must still match
TEST(TestRaspTransformersIntegration, LfiMatchWithUnappliedTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.io.fs.file"), alloc),
        STRL("/var/www/html/../../../etc/passwd"), alloc);
    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        {{"file", "../../../etc/passwd"}}, alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(
        out, {.id = "rasp-lfi",
                 .name = "LFI Exploit detection",
                 .tags = {{"type", "lfi"}, {"category", "exploit_detection"}, {"module", "rasp"}},
                 .matches = {{.op = "lfi_detector",
                     .highlight = "../../../etc/passwd"sv,
                     .args = {{.name = "resource",
                                  .value = "/var/www/html/../../../etc/passwd"sv,
                                  .address = "server.io.fs.file"},
                         {.name = "params",
                             .value = "../../../etc/passwd"sv,
                             .address = "server.request.query",
                             .path = {"file"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRaspTransformersIntegration, SsrfMatchWithTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.io.net.url"), alloc),
        STRL("https://internal-website.evil.com/path/to/stuffs?bla=42"), alloc);
    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        {{"path", ".evil.com%2Fpath%2Fto%2Fstuffs%3F"}}, alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(out,
        {.id = "rasp-ssrf",
            .name = "SSRF Exploit detection",
            .tags = {{"type", "ssrf"}, {"category", "exploit_detection"}, {"module", "rasp"}},
            .matches = {{.op = "ssrf_detector",
                .highlight = ".evil.com/path/to/stuffs?"sv,
                .args = {{.name = "resource",
                             .value = "https://internal-website.evil.com/path/to/stuffs?bla=42"sv,
                             .address = "server.io.net.url"},
                    {.name = "params",
                        .value = ".evil.com/path/to/stuffs?"sv,
                        .address = "server.request.query",
                        .path = {"path"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRaspTransformersIntegration, SqliMatchWithTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 3, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.db.statement"), alloc),
        STRL(R"(SELECT * FROM t WHERE id = '' OR '1'='1')"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("server.db.system"), alloc), STRL("mysql"), alloc);
    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        {{"id", "%27%20OR%20%271%27%3D%271"}}, alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(out,
        {.id = "rasp-sqli",
            .name = "SQLi Exploit detection",
            .tags = {{"type", "sqli"}, {"category", "exploit_detection"}, {"module", "rasp"}},
            .matches = {{.op = "sqli_detector",
                .highlight = R"(' OR '1'='1)"sv,
                .args = {{.name = "resource",
                             .value = R"(SELECT * FROM t WHERE id = ? OR ?=?)"sv,
                             .address = "server.db.statement"},
                    {.name = "params",
                        .value = R"(' OR '1'='1)"sv,
                        .address = "server.request.query",
                        .path = {"id"}},
                    {.name = "db_type", .value = "mysql"sv, .address = "server.db.system"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRaspTransformersIntegration, ShiMatchWithMultipleTransformers)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.sys.shell.cmd"), alloc),
        STRL("ls -l; cat /etc/passwd"), alloc);
    // base64("%3B%20cat%20%2Fetc%2Fpasswd")
    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        {{"cmd", "JTNCJTIwY2F0JTIwJTJGZXRjJTJGcGFzc3dk"}}, alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(
        out, {.id = "rasp-shi",
                 .name = "SHi Exploit detection",
                 .tags = {{"type", "shi"}, {"category", "exploit_detection"}, {"module", "rasp"}},
                 .matches = {{.op = "shi_detector",
                     .highlight = "; cat /etc/passwd"sv,
                     .args = {{.name = "resource",
                                  .value = "ls -l; cat /etc/passwd"sv,
                                  .address = "server.sys.shell.cmd"},
                         {.name = "params",
                             .value = "; cat /etc/passwd"sv,
                             .address = "server.request.query",
                             .path = {"cmd"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

// keys_only and values_only only alter the data source of the target, which is
// not used by the exploit prevention operators; the remaining transformers must
// still be applied to both keys and values
TEST(TestRaspTransformersIntegration, SourceTransformersIgnored)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("source_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        // keys_only on the params of an LFI rule, payload within the value
        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.io.fs.file"), alloc),
            STRL("/var/www/html/../../../etc/passwd"), alloc);
        set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
            {{"file", "..%2F..%2F..%2Fetc%2Fpasswd"}}, alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(out,
            {.id = "rasp-lfi-keys-only",
                .name = "LFI Exploit detection",
                .tags = {{"type", "lfi"}, {"category", "exploit_detection"}, {"module", "rasp"}},
                .matches = {{.op = "lfi_detector",
                    .highlight = "../../../etc/passwd"sv,
                    .args = {{.name = "resource",
                                 .value = "/var/www/html/../../../etc/passwd"sv,
                                 .address = "server.io.fs.file"},
                        {.name = "params",
                            .value = "../../../etc/passwd"sv,
                            .address = "server.request.query",
                            .path = {"file"}}}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        // values_only on the params of a SHi rule, payload within the key
        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.sys.shell.cmd"), alloc),
            STRL("ls -l; cat /etc/passwd"), alloc);
        set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
            {{"%3B%20cat%20%2Fetc%2Fpasswd", "value"}}, alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(out,
            {.id = "rasp-shi-values-only",
                .name = "SHi Exploit detection",
                .tags = {{"type", "shi"}, {"category", "exploit_detection"}, {"module", "rasp"}},
                .matches = {{.op = "shi_detector",
                    .highlight = "; cat /etc/passwd"sv,
                    .args = {{.name = "resource",
                                 .value = "ls -l; cat /etc/passwd"sv,
                                 .address = "server.sys.shell.cmd"},
                        {.name = "params",
                            .value = "; cat /etc/passwd"sv,
                            .address = "server.request.query",
                            .path = {"%3B%20cat%20%2Fetc%2Fpasswd"}}}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestRaspTransformersIntegration, CmdiMatchWithTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_handle handle = init_waf("rasp_transformers.yaml");
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 2, alloc);

    auto *exec = ddwaf_object_insert_key(&root, STRL("server.sys.exec.cmd"), alloc);
    ddwaf_object_set_array(exec, 3, alloc);
    ddwaf_object_set_string(ddwaf_object_insert(exec, alloc), STRL("/bin/sh"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert(exec, alloc), STRL("-c"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert(exec, alloc), STRL("ls -l"), alloc);

    set_string_map(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        {{"cmd", "ls%20-l"}}, alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(
        out, {.id = "rasp-cmdi",
                 .name = "CMDi Exploit detection",
                 .tags = {{"type", "cmdi"}, {"category", "exploit_detection"}, {"module", "rasp"}},
                 .matches = {{.op = "cmdi_detector",
                     .highlight = "ls -l"sv,
                     .args = {{.name = "resource",
                                  .value = R"(/bin/sh "-c" "ls -l")"sv,
                                  .address = "server.sys.exec.cmd"},
                         {.name = "params",
                             .value = "ls -l"sv,
                             .address = "server.request.query",
                             .path = {"cmd"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
