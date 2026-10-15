// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "canon.hpp"

#include <algorithm>
#include <cstdio>
#include <string_view>
#include <utility>
#include <vector>

namespace bench {
namespace {

void escape(std::string &out, std::string_view s)
{
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20 || c >= 0x7f) {
                // bytes, not code points: only meant to be stable and parseable
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

bool is_masked_key(std::string_view k)
{
    return k == "duration" || k == "block_id" || k == "stack_id" || k == "security_response_id";
}

void render(std::string &out, const ddwaf_object *obj)
{
    if (obj == nullptr || ddwaf_object_is_invalid(obj)) {
        out += "<invalid>";
    } else if (ddwaf_object_is_null(obj)) {
        out += "null";
    } else if (ddwaf_object_is_bool(obj)) {
        out += ddwaf_object_get_bool(obj) ? "true" : "false";
    } else if (ddwaf_object_is_signed(obj)) {
        out += std::to_string(ddwaf_object_get_signed(obj));
    } else if (ddwaf_object_is_unsigned(obj)) {
        out += std::to_string(ddwaf_object_get_unsigned(obj));
        out += 'u';
    } else if (ddwaf_object_is_float(obj)) {
        char buf[40];
        snprintf(buf, sizeof(buf), "%.17g", ddwaf_object_get_float(obj));
        out += buf;
    } else if (ddwaf_object_is_string(obj)) {
        std::size_t len = 0;
        const char *s = ddwaf_object_get_string(obj, &len);
        escape(out, {s, len});
    } else if (ddwaf_object_is_array(obj)) {
        const std::size_t n = ddwaf_object_get_size(obj);
        out += '[';
        for (std::size_t i = 0; i < n; ++i) {
            if (i != 0) { out += ','; }
            render(out, ddwaf_object_at_value(obj, i));
        }
        out += ']';
    } else if (ddwaf_object_is_map(obj)) {
        const std::size_t n = ddwaf_object_get_size(obj);
        std::vector<std::pair<std::string, std::string>> items;
        items.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            const ddwaf_object *k = ddwaf_object_at_key(obj, i);
            std::size_t klen = 0;
            const char *kstr = k != nullptr ? ddwaf_object_get_string(k, &klen) : nullptr;
            std::string key = kstr != nullptr ? std::string{kstr, klen} : std::string{};
            std::string val;
            if (is_masked_key(key)) {
                val = "<masked>";
            } else {
                render(val, ddwaf_object_at_value(obj, i));
            }
            items.emplace_back(std::move(key), std::move(val));
        }
        std::sort(items.begin(), items.end());
        out += '{';
        for (std::size_t i = 0; i < items.size(); ++i) {
            if (i != 0) { out += ','; }
            escape(out, items[i].first);
            out += ':';
            out += items[i].second;
        }
        out += '}';
    } else {
        out += "<unknown>";
    }
}

} // namespace

std::string canonical_json(const ddwaf_object *obj)
{
    std::string out;
    render(out, obj);
    return out;
}

} // namespace bench
