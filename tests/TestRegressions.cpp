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
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    char buffer[DDWAF_MAX_STRING_LENGTH + 4] = { 0 };
    const uint8_t emoji[]                    = { 0xe2, 0x98, 0xa2 };
    memset(buffer, 'A', sizeof(buffer));
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 2], emoji, sizeof(emoji));

    ddwaf_object map = DDWAF_OBJECT_MAP, string;
    ddwaf_object_stringl(&string, buffer, sizeof(buffer));
    ddwaf_object_map_add(&map, "value", &string);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MONITOR);

    //We should have matched something
    ASSERT_EQ(out.action, DDWAF_MONITOR);

    //The emoji should be trimmed out of the result
    EXPECT_TRUE(memchr(out.data, emoji[0], strlen(out.data)) == NULL);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRegression, DISABLED_segfault)
{
    /* const char * jsonFile = readFile("processor_libinj_xss.json");*/
    //ASSERT_TRUE(jsonFile != nullptr);
    //ASSERT_TRUE(pw_init("rule", jsonFile, NULL, NULL));
    //free((void*) jsonFile);

    //ddwaf_object map = DDWAF_OBJECT_MAP, string = pw_createString("style=e");
    //pw_addMap(&map, "value", 0, string);

    //ddwaf_result out = pw_run("rule", map, 2000);

    ////We should have matched something
    //EXPECT_EQ(out.action, DDWAF_MONITOR);

    //ddwaf_object_free(&map);
    //ddwaf_result_free(&out);
    /*pw_clearRule("rule");*/
}
