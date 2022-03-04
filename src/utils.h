// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef utils_h
#define utils_h

#include <optional>
#include <stdint.h>

template <typename T>
using optional_ref = std::optional<std::reference_wrapper<T>>;

size_t findStringCutoff(const char* str, size_t length);

//Internals
#define OBJ_HAS_KEY(obj, key) (obj.IsObject() && obj.HasMember(key))
#define OBJ_HAS_KEY_AS_STRING(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsString())
#define OBJ_HAS_KEY_AS_BOOL(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsBool())
#define OBJ_HAS_KEY_AS_INT(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsInt64())
#define OBJ_HAS_KEY_AS_UINT OBJ_HAS_KEY_AS_UINT64
#define OBJ_HAS_KEY_AS_UINT32(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsUint())
#define OBJ_HAS_KEY_AS_UINT64(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsUint64())
#define OBJ_HAS_KEY_AS_ARRAY(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsArray())
#define OBJ_HAS_KEY_AS_OBJECT(obj, key) (OBJ_HAS_KEY(obj, key) && obj[key].IsObject())

#define PWI_DATA_TYPES (DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED | DDWAF_OBJ_STRING)
#define PWI_CONTAINER_TYPES (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP)

// Rule constants
#define MAX_MATCH_COUNT 16 // Match the type size of RuleMatchTarget::matchGroup, don't increase past 16 without carefully updating the code
#define ADDITIVE_BUFFER_PREALLOC 8
#define TIME_STORE_DEFAULT 5

// Flow steps
#define EXIT_PREFIX "exit_"
#define EXIT_FLOW_OK "exit_flow"
#define EXIT_FLOW_MONITOR "exit_monitor"
#define EXIT_FLOW_BLOCK "exit_block"

// Steps we want to add:
// - exit_denylist
// - exit_allowlist
// - exit_needrasp
// - exit_norasp
// - exit_needwaf
// - exit_nowaf
// - exit_needrasp_nowaf
// - exit_needrasp_needwaf
// - exit_norasp_nowaf
// - exit_flagreq_{0-9} (write {0-9} to a standard key in the store)
// - exit_report_signal (report the request through a signal format defined in the rule)
// - exit_pentest (pentest: Sqreen should monitor but don't block the request)

#if defined(TESTING) && !defined(FRIEND_TEST)
// The build system to get gtest is more trouble than it's worth for a single define used only for testing
//#include <gtest/gtest_prod.h>
#define FRIEND_TEST(test_case_name, test_name) friend class test_case_name##_##test_name##_Test
#endif

#ifdef TESTING
#define PROD_STATIC
#else
#define PROD_STATIC static
#endif

// IP Utils
typedef struct
{
    uint8_t ip[16]; // big endian
    bool isIPv6;
} parsed_ip;

// Need the ddwaf_object declaration
#if !defined(pw_h)
#include <ddwaf.h>
#endif

#endif /* utils_h */
