// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

// Canonical JSON rendering of ddwaf_object results, used to detect behaviour
// changes between libddwaf revisions. Map keys are sorted (key order is not
// part of the contract); array order is preserved. Fields that are expected
// to differ between runs (timings, random block/stack ids) are masked.

#pragma once

#include <cstdint>
#include <string>

#include "ddwaf.h"

namespace bench {

std::string canonical_json(const ddwaf_object *obj);

// 64-bit FNV-1a, enough for digests compared within one invocation.
inline uint64_t fnv1a(const std::string &s, uint64_t h = 0xcbf29ce484222325ULL)
{
    for (unsigned char c : s) {
        h ^= c;
        h *= 0x100000001b3ULL;
    }
    return h;
}

} // namespace bench
