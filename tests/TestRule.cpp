// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

void compareArraysOfTargets(const PWManifest& manifest, const rapidjson::Value& _array1, const vector<PWManifest::ARG_ID>& array2)
{
    const auto& array1 = _array1.GetArray();

    ASSERT_EQ(array1.Size(), array2.size());

    for (uint32_t i = 0, length = array1.Size(); i < length; ++i)
    {
        EXPECT_EQ(manifest.getTargetArgID(array1[i].GetString()), array2[i]);
    }
}

TEST(TestRule, TestRuleDoMatchInvalidParameters)
{
    //Initialize a PowerWAF rule

    auto rule_ = readFile("powerwaf.yaml");
    ASSERT_TRUE(rule_.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule_, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule_);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    //Access the rule
    PowerWAF* waf         = reinterpret_cast<PowerWAF*>(handle);
    const condition& cond = waf->rules.find("1")->second.conditions[0];

    //Send garbage input
    PWRetriever retriever(waf->manifest, 256, 256);
    PWRetriever::Iterator iterator(retriever);

    //Try to trigger a null pointer deref
    ddwaf_object parameter = DDWAF_OBJECT_INVALID;
    const char* val        = "randomString";

    parameter.type        = DDWAF_OBJ_STRING;
    parameter.stringValue = val;
    parameter.nbEntries   = strlen(val);
    iterator.argsIterator.reset(&parameter);

    std::vector<uint8_t> submatch;
    MatchGatherer gather(submatch);
    gather.resolvedValue = "lol";
    gather.matchedValue  = "lol2";

    EXPECT_FALSE(cond.matchWithTransformer(*iterator, gather, false, true));
    EXPECT_EQ(gather.resolvedValue, "lol");
    EXPECT_EQ(gather.matchedValue, "lol2");

    parameter.parameterName = "";
    EXPECT_FALSE(cond.matchWithTransformer(*iterator, gather, false, true));
    EXPECT_EQ(gather.resolvedValue, "lol");
    EXPECT_EQ(gather.matchedValue, "lol2");

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
