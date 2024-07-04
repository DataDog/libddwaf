// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "obfuscator.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestObfuscator, TestKeyValueObfuscator)
{
    ddwaf::obfuscator event_obfuscator("^password$"sv, "value"sv);

    EXPECT_TRUE(event_obfuscator.is_sensitive_key("password"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("passworde"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("random"sv));

    EXPECT_TRUE(event_obfuscator.is_sensitive_value("random value"sv));
    EXPECT_TRUE(event_obfuscator.is_sensitive_value("value"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_value("random"sv));
}

TEST(TestObfuscator, TestKeyObfuscator)
{
    ddwaf::obfuscator event_obfuscator("^password$"sv);

    EXPECT_TRUE(event_obfuscator.is_sensitive_key("password"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("passworde"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("random"sv));

    EXPECT_FALSE(event_obfuscator.is_sensitive_value("random value"sv));
}

TEST(TestObfuscator, TestValueObfuscator)
{
    ddwaf::obfuscator event_obfuscator({}, "value"sv);

    EXPECT_FALSE(event_obfuscator.is_sensitive_key("password"sv));

    EXPECT_TRUE(event_obfuscator.is_sensitive_value("random value"sv));
    EXPECT_TRUE(event_obfuscator.is_sensitive_value("value"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_value("random"sv));
}

TEST(TestObfuscator, TestEmptyObfuscator)
{
    ddwaf::obfuscator event_obfuscator;

    EXPECT_FALSE(event_obfuscator.is_sensitive_key("password"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_value("value"sv));
}

TEST(TestObfuscator, TestDefaultObfuscator)
{
    std::vector<std::string> samples{"password", "pwd", "pword", "passwd", "pass", "passphrase",
        "pass-phrase", "passphrase", "secret", "api_key", "api-key", "apikey", "private_key",
        "private-key", "privatekey", "public-key", "public_key", "publickey", "secret_key",
        "secret-key", "secretkey", "accesskey", "access_key", "access-key", "auth-token",
        "auth_token", "authtoken", "access-token", "access_token", "accesstoken", "id-token",
        "id_token", "idtoken", "refresh_token", "refresh-token", "refreshtoken", "consumer-id",
        "consumer_id", "consumerid", "consumer-key", "consumer_key", "consumerkey",
        "consumer-secret", "consumer_secret", "consumersecret", "signed", "signature", "bearer",
        "authorization", "jsessionid", "phpsessid", "asp.net_sessionid", "asp.net-sessionid", "sid",
        "jwt", "PASSWORD", "PWD", "PWORD", "PASSWD", "PASS", "PASSPHRASE", "PASS-PHRASE",
        "PASSPHRASE", "SECRET", "API_KEY", "API-KEY", "APIKEY", "PRIVATE_KEY", "PRIVATE-KEY",
        "PRIVATEKEY", "PUBLIC-KEY", "PUBLIC_KEY", "PUBLICKEY", "SECRET_KEY", "SECRET-KEY",
        "SECRETKEY", "ACCESSKEY", "ACCESS_KEY", "ACCESS-KEY", "AUTH-TOKEN", "AUTH_TOKEN",
        "AUTHTOKEN", "ACCESS-TOKEN", "ACCESS_TOKEN", "ACCESSTOKEN", "ID-TOKEN", "ID_TOKEN",
        "IDTOKEN", "REFRESH_TOKEN", "REFRESH-TOKEN", "REFRESHTOKEN", "CONSUMER-ID", "CONSUMER_ID",
        "CONSUMERID", "CONSUMER-KEY", "CONSUMER_KEY", "CONSUMERKEY", "CONSUMER-SECRET",
        "CONSUMER_SECRET", "CONSUMERSECRET", "SIGNED", "SIGNATURE", "BEARER", "AUTHORIZATION",
        "JSESSIONID", "PHPSESSID", "ASP.NET_SESSIONID", "ASP.NET-SESSIONID", "SID", "JWT"
    };

    ddwaf::obfuscator event_obfuscator{ddwaf::obfuscator::default_key_regex_str, {}};
    for (auto &sample : samples) { EXPECT_TRUE(event_obfuscator.is_sensitive_key(sample)); }
}

TEST(TestObfuscator, TestConfigKeyValue)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {"password", "rule1_obf"}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1_obf"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Both
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1_obf"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscator, TestConfigKey)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {"password", nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1_obf"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1_obf",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscator, TestConfigValue)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, "rule1_obf"}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1_obf"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscator, TestConfigHighlight)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, "^badvalue$"}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // Highlight obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "badvalue_something"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "security_scanner"}, {"category", "category2"}},
                               .matches = {{.op = "phrase_match",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // No obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "othervalue_badvalue"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "security_scanner"}, {"category", "category2"}},
                               .matches = {{.op = "phrase_match",
                                   .highlight = "othervalue",
                                   .args = {{
                                       .value = "othervalue_badvalue",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscator, TestConfigEmpty)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, ""}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1_obf"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1_obf",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscator, TestInvalidConfigKey)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {"[", nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>",
                                   .args = {{
                                       .value = "<Redacted>",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1_obf"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1_obf",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscator, TestInvalidConfigValue)
{
    auto rule = read_file("obfuscator.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, "]"}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, inter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&inter, "passwordle", ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value", &inter);

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1",
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1_obf"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1",
                                   .args = {{
                                       .value = "rule1_obf",
                                       .address = "value",
                                   }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
