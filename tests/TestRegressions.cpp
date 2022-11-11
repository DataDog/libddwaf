// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestRegressions, TruncatedUTF8)
{
    auto rule = readFile("regressions.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    char buffer[DDWAF_MAX_STRING_LENGTH + 4] = {0};
    const uint8_t emoji[] = {0xe2, 0x98, 0xa2};
    memset(buffer, 'A', sizeof(buffer));
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 2], emoji, sizeof(emoji));

    ddwaf_object map = DDWAF_OBJECT_MAP, string;
    ddwaf_object_stringl(&string, buffer, sizeof(buffer));
    ddwaf_object_map_add(&map, "value", &string);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    // The emoji should be trimmed out of the result
    EXPECT_TRUE(memchr(out.data, emoji[0], strlen(out.data)) == NULL);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRegressions, DuplicateFlowMatches)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("regressions2.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&parameter, "param1", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&parameter, "param2", ddwaf_object_string(&tmp, "Duplicate"));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &parameter, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    EXPECT_STREQ(ret.data,
        R"([{"rule":{"id":"2","name":"rule2","tags":{"type":"flow1","category":"category2"}},"rule_matches":[{"operator":"match_regex","operator_value":"Sqreen","parameters":[{"address":"param1","key_path":[],"value":"Sqreen","highlight":["Sqreen"]}]},{"operator":"match_regex","operator_value":"Duplicate","parameters":[{"address":"param2","key_path":[],"value":"Duplicate","highlight":["Duplicate"]}]}]}])");

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
