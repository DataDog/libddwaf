// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// 1s and 1us
#define LONG_TIME 1000000
#define SHORT_TIME 1

#define DDWAF_OBJECT_INVALID                                                                       \
  {                                                                                                \
    NULL, 0, {NULL}, 0, DDWAF_OBJ_INVALID                                                          \
  }
#define DDWAF_OBJECT_MAP                                                                           \
  {                                                                                                \
    NULL, 0, {NULL}, 0, DDWAF_OBJ_MAP                                                              \
  }
#define DDWAF_OBJECT_ARRAY                                                                         \
  {                                                                                                \
    NULL, 0, {NULL}, 0, DDWAF_OBJ_ARRAY                                                            \
  }
#define DDWAF_OBJECT_SIGNED_FORCE(value)                                                           \
  {                                                                                                \
    NULL, 0, {(const char *)value}, 0, DDWAF_OBJ_SIGNED                                            \
  }
#define DDWAF_OBJECT_UNSIGNED_FORCE(value)                                                         \
  {                                                                                                \
    NULL, 0, {(const char *)value}, 0, DDWAF_OBJ_UNSIGNED                                          \
  }
#define DDWAF_OBJECT_STRING_PTR(string, length)                                                    \
  {                                                                                                \
    NULL, 0, {string}, length, DDWAF_OBJ_STRING                                                    \
  }

#define EXPECT_STR(a, b) EXPECT_STREQ(a.c_str(), b)
#define EXPECT_STRV(a, b) EXPECT_STREQ(a.data(), b)
