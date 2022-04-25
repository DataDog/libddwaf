// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <string>

#include "utils.hpp"

namespace ddwaf::benchmark::utils
{

namespace {
void debug_str_helper(std::string &res, const ddwaf_object &p)
{
    if (p.parameterNameLength != 0U) {
        res += p.parameterName;
        res += ": ";
    }
    switch (p.type) {
    case DDWAF_OBJ_INVALID:
        res += "<invalid>";
        break;
    case DDWAF_OBJ_SIGNED:
        res += std::to_string(p.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        res += std::to_string(p.uintValue);
        break;
    case DDWAF_OBJ_STRING:
        res += '"';
        res += std::string_view{p.stringValue, p.nbEntries};
        res += '"';
        break;
    case DDWAF_OBJ_ARRAY:
        res += '[';
        for (decltype(p.nbEntries) i = 0; i < p.nbEntries; i++) {
            debug_str_helper(res, p.array[i]);
            if (i != p.nbEntries - 1) {
                res += ", ";
            }
        }
        res += ']';
        break;
    case DDWAF_OBJ_MAP:
        res += '{';
        for (decltype(p.nbEntries) i = 0; i < p.nbEntries; i++) {
            debug_str_helper(res, p.array[i]);
            if (i != p.nbEntries - 1) {
                res += ", ";
            }
        }
        res += '}';
        break;
    }
}
} // namespace

std::string object_to_string(const ddwaf_object &o) noexcept
{
    std::string res;
    debug_str_helper(res, o);
    return res;
}

}
