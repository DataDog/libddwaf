// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "obfuscator.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestObfuscator, IsSensitiveKeyValue)
{
    ddwaf::obfuscator event_obfuscator("^password$"sv, "value"sv);

    EXPECT_TRUE(event_obfuscator.is_sensitive_key("password"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("passworde"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("random"sv));

    EXPECT_TRUE(event_obfuscator.is_sensitive_value("random value"sv));
    EXPECT_TRUE(event_obfuscator.is_sensitive_value("value"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_value("random"sv));
}

TEST(TestObfuscator, IsSensitiveKey)
{
    ddwaf::obfuscator event_obfuscator("^password$"sv);

    EXPECT_TRUE(event_obfuscator.is_sensitive_key("password"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("passworde"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_key("random"sv));

    EXPECT_FALSE(event_obfuscator.is_sensitive_value("random value"sv));
}

TEST(TestObfuscator, IsSensitiveValue)
{
    ddwaf::obfuscator event_obfuscator({}, "value"sv);

    EXPECT_FALSE(event_obfuscator.is_sensitive_key("password"sv));

    EXPECT_TRUE(event_obfuscator.is_sensitive_value("random value"sv));
    EXPECT_TRUE(event_obfuscator.is_sensitive_value("value"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_value("random"sv));
}

TEST(TestObfuscator, IsSensitiveKeyValueNoRegexes)
{
    ddwaf::obfuscator event_obfuscator;

    EXPECT_FALSE(event_obfuscator.is_sensitive_key("password"sv));
    EXPECT_FALSE(event_obfuscator.is_sensitive_value("value"sv));
}

TEST(TestObfuscator, IsSensitiveKeyDefaultRegex)
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
        "JSESSIONID", "PHPSESSID", "ASP.NET_SESSIONID", "ASP.NET-SESSIONID", "SID", "JWT"};

    ddwaf::obfuscator event_obfuscator{ddwaf::obfuscator::default_key_regex_str, {}};
    for (auto &sample : samples) { EXPECT_TRUE(event_obfuscator.is_sensitive_key(sample)); }
}

TEST(TestObfuscator, MatchObfuscationCustomRegexes)
{
    ddwaf::obfuscator event_obfuscator("^password$"sv, "value"sv);
    {
        // Verify that when the key matches, both value and highlight are redacted
        condition_match match{
            .args = {{.name = "input", .resolved = "random", .key_path = {"password"}}},
            .highlights = {"random"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], obfuscator::redaction_msg);
        EXPECT_STR(match.args[0].resolved, obfuscator::redaction_msg);
    }

    {
        // Verify that the value is redacted when it matches the regex and that
        // the highlight is redacted due to the condition argument being input
        condition_match match{
            .args = {{.name = "input", .resolved = "value", .key_path = {"unrelated"}}},
            .highlights = {"not sensitive"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], obfuscator::redaction_msg);
        EXPECT_STR(match.args[0].resolved, obfuscator::redaction_msg);
    }

    {
        // Verify that the value is redacted when it matches the regex and that
        // the highlight is redacted due to the condition argument being param
        condition_match match{
            .args = {{.name = "params", .resolved = "value", .key_path = {"unrelated"}}},
            .highlights = {"not sensitive"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], obfuscator::redaction_msg);
        EXPECT_STR(match.args[0].resolved, obfuscator::redaction_msg);
    }

    {
        // Verify that the value is redacted when it matches the regex and that
        // the highlight isn't because it isn't related to the value
        condition_match match{.args = {{.name = "unrelated to highlight",
                                  .resolved = "value",
                                  .key_path = {"unrelated"}}},
            .highlights = {"not sensitive"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], "not sensitive");
        EXPECT_STR(match.args[0].resolved, obfuscator::redaction_msg);
    }

    {
        // Verify that the highlight is only redacted when the value is
        condition_match match{
            .args = {{.name = "params", .resolved = "not sensitive", .key_path = {"unrelated"}}},
            .highlights = {"value"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], "value");
        EXPECT_STR(match.args[0].resolved, "not sensitive");
    }

    {
        // Verify that when neither the key nor the value match, no redaction is
        // performed
        condition_match match{
            .args = {{.name = "input", .resolved = "random", .key_path = {"unredacted"}}},
            .highlights = {"random"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], "random");
        EXPECT_STR(match.args[0].resolved, "random");
    }
}

TEST(TestObfuscator, MatchObfuscationDefaultRegexes)
{
    ddwaf::obfuscator event_obfuscator{
        obfuscator::default_key_regex_str, obfuscator::default_value_regex_str};

    {
        // Verify that when the key matches, both value and highlight are redacted
        condition_match match{
            .args = {{.name = "input", .resolved = "random", .key_path = {"password"}}},
            .highlights = {"random"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], obfuscator::redaction_msg);
        EXPECT_STR(match.args[0].resolved, obfuscator::redaction_msg);
    }

    {
        // Verify that the value is redacted when it matches the regex and that
        // the highlight is redacted due to the condition argument being input
        condition_match match{.args = {{.name = "input", .resolved = "password=something"}},
            .highlights = {"not sensitive"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], obfuscator::redaction_msg);
        EXPECT_STR(match.args[0].resolved, "password=<Redacted>");
    }

    {
        // Verify that the value is redacted when it matches the regex and that
        // the highlight is redacted due to the condition argument being param
        condition_match match{.args = {{.name = "params",
                                  .resolved = "token:qweqweqweqweq",
                                  .key_path = {"unrelated"}}},
            .highlights = {"not sensitive"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], obfuscator::redaction_msg);
        EXPECT_STR(match.args[0].resolved, "token:<Redacted>");
    }

    {
        // Verify that the value is redacted when it matches the regex and that
        // the highlight isn't because the it isn't related to the value
        condition_match match{.args = {{.name = "unrelated to highlight",
                                  .resolved = "ssh-rsa "
                                              "1234567890123456789012345678901234567890123456789012"
                                              "345678901234567890123456789012345678901234567890",
                                  .key_path = {"unrelated"}}},
            .highlights = {"not sensitive"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], "not sensitive");
        EXPECT_STR(match.args[0].resolved, "ssh-rsa <Redacted>");
    }

    {
        // Verify that the highlight is only redacted when the value is
        condition_match match{
            .args = {{.name = "params", .resolved = "not sensitive", .key_path = {"unrelated"}}},
            .highlights = {"password=2020"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], "password=2020");
        EXPECT_STR(match.args[0].resolved, "not sensitive");
    }

    {
        // Verify that when neither the key nor the value match, no redaction is
        // performed
        condition_match match{
            .args = {{.name = "input", .resolved = "random", .key_path = {"unredacted"}}},
            .highlights = {"random"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.highlights[0], "random");
        EXPECT_STR(match.args[0].resolved, "random");
    }
}

TEST(TestObfuscator, ValueObfuscationDefaultRegexes)
{
    std::vector<std::pair<std::string_view, std::string_view>> test_cases{
        {R"(blapassword=123456&)", R"(blapassword=<Redacted>&)"},
        {R"(password=SuperSecret123)", R"(password=<Redacted>)"},
        {R"(asp.net-sessionid=qwertyuiop1234567890)", R"(asp.net-sessionid=<Redacted>)"},
        {R"(api_key="12345-abcde-67890-fghij")", R"(api_key=<Redacted>)"},
        {R"(refresh_token=xyz098zyx7654321)", R"(refresh_token=<Redacted>)"},
        {R"("password":123)", R"("password":<Redacted>)"},
        {R"("password":"123",)", R"("password":<Redacted>,)"},
        {R"("token":"abc123def456ghi789")", R"("token":<Redacted>)"},
        {R"(bla.com/?password=123&v=x)", R"(bla.com/?password=<Redacted>&v=x)"},
        {R"(bla.com/?v=x&password=123&v=x)", R"(bla.com/?v=x&password=<Redacted>&v=x)"},
        {R"(bearer qweqweqweqewqew)", R"(bearer <Redacted>)"},
        {R"(Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9)", R"(Bearer <Redacted>)"},
        {R"(token:qweqweqweqweq)", R"(token:<Redacted>)"},
        {R"(gho_123456789012345678901234567890123456)", R"(gho_<Redacted>)"},
        {R"(ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd)", R"(ghp_<Redacted>abcd)"},
        {R"(eyIqwe.eyIqwe.eyqweqwe)", R"(eyIqwe.<Redacted>)"},
        {R"(eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidXNlcklkIn0.KvBcTejQwR6j1z2y3x4v)",
            R"(eyJhbGciOiJIUzI1NiJ9.<Redacted>)"},
        {R"(-----BEGIN PRIVATE KEY-----qwe-----END PRIVATE KEY)",
            R"(-----BEGIN PRIVATE KEY-----<Redacted>-----END PRIVATE KEY)"},
        {R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwKFIxQKIn8FJyX1TqV2QIDAQABAoIBAQC/UYHm6+NHmY6U
-----END RSA PRIVATE KEY-----)",
            R"(-----BEGIN RSA PRIVATE KEY-----<Redacted>-----END RSA PRIVATE KEY-----)"},

        {R"(ssh-rsa 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890)",
            R"(ssh-rsa <Redacted>)"},
        {R"(ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1xjOvnPJuorR8lHymz4uoypHy1h7uMKw29lJr3p6eJ6OxNc1Rkqv8hDxnN9nJSxIOLRG2fDu1K5XmRe+Jp0iYzPcwupTV6Mg93clo0BhE0mzwIoxFDq2w==)",
            R"(ssh-rsa <Redacted>==)"},
        {R"(site.com/?api_token=sensitive&value=something&PHPSESSID=something&json={"token":"value","somethingelse":"ghp_000000000000000000000000000000000000"})",
            R"(site.com/?api_token=<Redacted>&value=something&PHPSESSID=<Redacted>&json={"token":<Redacted>,"somethingelse":"ghp_<Redacted>"})"},
    };

    ddwaf::obfuscator event_obfuscator{
        obfuscator::default_key_regex_str, obfuscator::default_value_regex_str};

    for (const auto &[original, expected] : test_cases) {
        condition_match match{.args = {{.name = "input", .resolved = original}},
            .highlights = {"random"},
            .operator_name = {},
            .operator_value = {}};

        event_obfuscator.obfuscate_match(match);
        EXPECT_STR(match.args[0].resolved, expected);
    }
}

} // namespace
