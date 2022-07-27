// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <gtest/gtest.h>
#include <re2/re2.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/prettywriter.h>
using namespace std;

#include <waf.hpp>
#include <context.hpp>
#include <clock.hpp>
#include <ddwaf.h>
#include <config.hpp>
#include <exception.hpp>
#include <ip_utils.hpp>
#include <log.hpp>
#include <obfuscator.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <ruleset_info.hpp>
#include <utils.h>
#include <yaml-cpp/yaml.h>

using namespace std::literals;

using namespace ddwaf;
// 1s and 1us
#define LONG_TIME 1000000
#define SHORT_TIME 1

extern ddwaf_object readFile(const char* filename);
extern ddwaf_object readRule(const char* rule);
extern void compareData(const char* rulename, ddwaf_object input, size_t time, const char* expectedOutput);

namespace YAML
{
template <>
struct as_if<ddwaf_object, void>
{
    explicit as_if(const Node& node_);
    ddwaf_object operator()() const;
    const Node& node;
};

}

#define DDWAF_OBJECT_INVALID                    \
    {                                           \
        NULL, 0, { NULL }, 0, DDWAF_OBJ_INVALID \
    }
#define DDWAF_OBJECT_MAP                    \
    {                                       \
        NULL, 0, { NULL }, 0, DDWAF_OBJ_MAP \
    }
#define DDWAF_OBJECT_ARRAY                    \
    {                                         \
        NULL, 0, { NULL }, 0, DDWAF_OBJ_ARRAY \
    }
#define DDWAF_OBJECT_SIGNED_FORCE(value)                      \
    {                                                         \
        NULL, 0, { (const char*) value }, 0, DDWAF_OBJ_SIGNED \
    }
#define DDWAF_OBJECT_UNSIGNED_FORCE(value)                      \
    {                                                           \
        NULL, 0, { (const char*) value }, 0, DDWAF_OBJ_UNSIGNED \
    }
#define DDWAF_OBJECT_STRING_PTR(string, length)       \
    {                                                 \
        NULL, 0, { string }, length, DDWAF_OBJ_STRING \
    }
