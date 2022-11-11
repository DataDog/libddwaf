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
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <re2/re2.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/prettywriter.h>
using namespace std;

#include <clock.hpp>
#include <config.hpp>
#include <context.hpp>
#include <ddwaf.h>
#include <exception.hpp>
#include <exclusion_filter.hpp>
#include <ip_utils.hpp>
#include <log.hpp>
#include <obfuscator.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <rule_data_dispatcher.hpp>
#include <ruleset_info.hpp>
#include <utils.h>
#include <waf.hpp>
#include <yaml-cpp/yaml.h>

#include <rule_processor/exact_match.hpp>
#include <rule_processor/ip_match.hpp>
#include <rule_processor/is_sqli.hpp>
#include <rule_processor/is_xss.hpp>
#include <rule_processor/phrase_match.hpp>
#include <rule_processor/regex_match.hpp>

#include "test_utils.hpp"

using namespace std::literals;
using namespace ddwaf;

// 1s and 1us
#define LONG_TIME 1000000
#define SHORT_TIME 1

#define DDWAF_OBJECT_INVALID                                                                       \
    {                                                                                              \
        NULL, 0, {NULL}, 0, DDWAF_OBJ_INVALID                                                      \
    }
#define DDWAF_OBJECT_MAP                                                                           \
    {                                                                                              \
        NULL, 0, {NULL}, 0, DDWAF_OBJ_MAP                                                          \
    }
#define DDWAF_OBJECT_ARRAY                                                                         \
    {                                                                                              \
        NULL, 0, {NULL}, 0, DDWAF_OBJ_ARRAY                                                        \
    }
#define DDWAF_OBJECT_SIGNED_FORCE(value)                                                           \
    {                                                                                              \
        NULL, 0, {(const char *)value}, 0, DDWAF_OBJ_SIGNED                                        \
    }
#define DDWAF_OBJECT_UNSIGNED_FORCE(value)                                                         \
    {                                                                                              \
        NULL, 0, {(const char *)value}, 0, DDWAF_OBJ_UNSIGNED                                      \
    }
#define DDWAF_OBJECT_STRING_PTR(string, length)                                                    \
    {                                                                                              \
        NULL, 0, {string}, length, DDWAF_OBJ_STRING                                                \
    }
