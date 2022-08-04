// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestPowerWAF, TestEmptyParameters)
{
    auto rule = readFile("powerwaf.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle);

    //Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_array(&tmp));

    //Detect match in a substructure's key
    EXPECT_EQ(ddwaf_run(context, &parameter, NULL, LONG_TIME), DDWAF_OK);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPowerWAF, TestLogging)
{
    static DDWAF_LOG_LEVEL lastLevel;
    static string lastFile;
    static string lastFunction;
    static string lastMessage;

    ddwaf_log_cb cb = [](DDWAF_LOG_LEVEL level, const char* function,
                         const char* file, unsigned line, const char* message,
                         uint64_t message_len) {
        lastLevel    = level;
        lastFunction = function;
        lastFile     = file;
        EXPECT_GT(line, 0);
        lastMessage = string { message, static_cast<size_t>(message_len) };
    };

    ddwaf_set_log_cb(cb, DDWAF_LOG_TRACE);

    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_TRACE);
    /*     the files emitting messages are expected to be in src/, so we*/
    //remove the number of characters in the full path up to src/.
    //But tests are in tests/, a sibling of src. Because tests is two chars
    /*longer than src, we get the "s/" in the beginning */
#ifdef _WIN32
    EXPECT_EQ(lastFile, "TestPowerWAF.cpp");
#else
    EXPECT_EQ(lastFile, "TestPowerWAF.cpp");
#endif
    EXPECT_TRUE(lastFunction.find("TestBody") != string::npos);
    EXPECT_EQ(lastMessage, "test message");

    ddwaf_set_log_cb(cb, DDWAF_LOG_TRACE);
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_TRACE);
    DDWAF_DEBUG("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_DEBUG);
    DDWAF_INFO("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_WARN("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_WARN);
    DDWAF_ERROR("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);

    ddwaf_set_log_cb(cb, DDWAF_LOG_DEBUG);
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_DEBUG("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_DEBUG);
    DDWAF_INFO("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_WARN("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_WARN);
    DDWAF_ERROR("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);

    ddwaf_set_log_cb(cb, DDWAF_LOG_INFO);
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_DEBUG("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_INFO("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_INFO);
    DDWAF_WARN("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_WARN);
    DDWAF_ERROR("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);

    ddwaf_set_log_cb(cb, DDWAF_LOG_WARN);
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_DEBUG("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_INFO("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_WARN("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_WARN);
    DDWAF_ERROR("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);

    ddwaf_set_log_cb(cb, DDWAF_LOG_ERROR);
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_DEBUG("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_INFO("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_WARN("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_ERROR("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);

    ddwaf_set_log_cb(cb, DDWAF_LOG_OFF);
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_TRACE("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_DEBUG("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_INFO("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_WARN("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);
    DDWAF_ERROR("test message");
    EXPECT_EQ(lastLevel, DDWAF_LOG_ERROR);

    DDWAF_WARN("ignored message"); // min level is ERROR here
    EXPECT_EQ(lastMessage, "test message");

    ddwaf_set_log_cb(nullptr, DDWAF_LOG_TRACE /* ignored */);
    DDWAF_INFO("another message");
    EXPECT_EQ(lastMessage, "test message");

    ddwaf_set_log_cb(cb, DDWAF_LOG_INFO);
    EXPECT_EQ(lastMessage, "Sending log messages to binding, min level info");
    DDWAF_INFO("Signed %d", -25);
    EXPECT_EQ(lastMessage, "Signed -25");
    DDWAF_INFO("Unsigned %u", 25);
    EXPECT_EQ(lastMessage, "Unsigned 25");
    DDWAF_INFO("String %s", "thisisastring");
    EXPECT_EQ(lastMessage, "String thisisastring");
    DDWAF_INFO("Combination %d %u %s %s %u %s", -1, 2, "abc", "def", 22, "ghi");
    EXPECT_EQ(lastMessage, "Combination -1 2 abc def 22 ghi");
}

TEST(TestPowerWAF, TestConfig)
{
    auto rule = readFile("powerwaf.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle);

    //Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule1"));

    //Detect match in a substructure's key
    EXPECT_EQ(ddwaf_run(context, &parameter, NULL, LONG_TIME), DDWAF_MATCH);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
