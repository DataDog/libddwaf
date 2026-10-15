// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "node.hpp"

#include <cstdio>

namespace bench {

void apply_limits(node &n, php_limits &lim, unsigned depth)
{
    switch (n.type) {
    case node::kind::array:
    case node::kind::map: {
        if (depth >= php_limits::max_depth || lim.elements_remaining == 0) {
            n = node::null();
            return;
        }
        --lim.elements_remaining;
        const std::size_t size = n.is_array() ? n.arr.size() : n.obj.size();
        const std::size_t keep = std::min(size, lim.elements_remaining);
        if (n.is_array()) {
            n.arr.resize(keep);
            for (auto &c : n.arr) { apply_limits(c, lim, depth + 1); }
        } else {
            n.obj.resize(keep);
            for (auto &[k, c] : n.obj) {
                if (k.size() > php_limits::max_string_length) {
                    k.resize(php_limits::max_string_length);
                }
                apply_limits(c, lim, depth + 1);
            }
        }
        return;
    }
    case node::kind::string:
        if (n.s.size() > php_limits::max_string_length) { n.s.resize(php_limits::max_string_length); }
        [[fallthrough]];
    default:
        if (lim.elements_remaining > 0) { --lim.elements_remaining; }
        return;
    }
}

void to_object(const node &n, ddwaf_object *out, ddwaf_allocator alloc)
{
    switch (n.type) {
    case node::kind::null:
        ddwaf_object_set_null(out);
        return;
    case node::kind::boolean:
        ddwaf_object_set_bool(out, n.b);
        return;
    case node::kind::integer:
        ddwaf_object_set_signed(out, n.i);
        return;
    case node::kind::string:
        ddwaf_object_set_string(out, n.s.data(), static_cast<uint32_t>(n.s.size()), alloc);
        return;
    case node::kind::array:
        // ddwaf_object_set_array maps to the large-capacity variant
        ddwaf_object_set_array(out, n.arr.size(), alloc);
        for (const auto &c : n.arr) { to_object(c, ddwaf_object_insert(out, alloc), alloc); }
        return;
    case node::kind::map:
        ddwaf_object_set_map(out, n.obj.size(), alloc);
        for (const auto &[k, c] : n.obj) {
            to_object(c,
                ddwaf_object_insert_key(out, k.data(), static_cast<uint32_t>(k.size()), alloc),
                alloc);
        }
        return;
    }
}

uint32_t flat_object::add_string(std::string_view s)
{
    const auto off = static_cast<uint32_t>(strings_.size());
    strings_.append(s);
    return off;
}

void flat_object::flatten(const node &n, std::string_view key)
{
    token t{n.type, add_string(key), static_cast<uint32_t>(key.size()), 0, 0};
    switch (n.type) {
    case node::kind::null: break;
    case node::kind::boolean: t.val = n.b ? 1 : 0; break;
    case node::kind::integer: t.val = static_cast<uint64_t>(n.i); break;
    case node::kind::string:
        t.off = add_string(n.s);
        t.val = n.s.size();
        break;
    case node::kind::array: t.val = n.arr.size(); break;
    case node::kind::map: t.val = n.obj.size(); break;
    }
    tokens_.push_back(t);
    if (n.type == node::kind::array) {
        for (const auto &c : n.arr) { flatten(c, {}); }
    } else if (n.type == node::kind::map) {
        for (const auto &[k, c] : n.obj) { flatten(c, k); }
    }
}

void flat_object::build_at(std::size_t &pos, ddwaf_object *out, ddwaf_allocator alloc) const
{
    const token &t = tokens_[pos++];
    switch (t.type) {
    case node::kind::null: ddwaf_object_set_null(out); return;
    case node::kind::boolean: ddwaf_object_set_bool(out, t.val != 0); return;
    case node::kind::integer: ddwaf_object_set_signed(out, static_cast<int64_t>(t.val)); return;
    case node::kind::string:
        ddwaf_object_set_string(out, strings_.data() + t.off, static_cast<uint32_t>(t.val), alloc);
        return;
    case node::kind::array:
        ddwaf_object_set_array(out, static_cast<std::size_t>(t.val), alloc);
        for (uint64_t i = 0; i < t.val; ++i) { build_at(pos, ddwaf_object_insert(out, alloc), alloc); }
        return;
    case node::kind::map:
        ddwaf_object_set_map(out, static_cast<std::size_t>(t.val), alloc);
        for (uint64_t i = 0; i < t.val; ++i) {
            const token &c = tokens_[pos];
            build_at(pos,
                ddwaf_object_insert_key(out, strings_.data() + c.key_off, c.key_len, alloc), alloc);
        }
        return;
    }
}

namespace {
void json_escape(std::string &out, std::string_view s)
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
            if (c < 0x20) {
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

void to_json_impl(std::string &out, const node &n)
{
    switch (n.type) {
    case node::kind::null: out += "null"; break;
    case node::kind::boolean: out += n.b ? "true" : "false"; break;
    case node::kind::integer: out += std::to_string(n.i); break;
    case node::kind::string: json_escape(out, n.s); break;
    case node::kind::array:
        out += '[';
        for (std::size_t i = 0; i < n.arr.size(); ++i) {
            if (i != 0) { out += ','; }
            to_json_impl(out, n.arr[i]);
        }
        out += ']';
        break;
    case node::kind::map:
        out += '{';
        for (std::size_t i = 0; i < n.obj.size(); ++i) {
            if (i != 0) { out += ','; }
            json_escape(out, n.obj[i].first);
            out += ':';
            to_json_impl(out, n.obj[i].second);
        }
        out += '}';
        break;
    }
}
} // namespace

std::string to_json(const node &n)
{
    std::string out;
    to_json_impl(out, n);
    return out;
}

} // namespace bench
