// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

// Small value tree used by the traffic generator. It is converted to a
// ddwaf_object through the public C API only, so the benchmark compiles
// unchanged against any libddwaf revision exposing the 2.x API.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ddwaf.h"

namespace bench {

struct node_kv;

struct node {
    enum class kind : uint8_t { null, boolean, integer, string, array, map };

    kind type{kind::null};
    bool b{false};
    int64_t i{0};
    std::string s;
    std::vector<node> arr;
    std::vector<node_kv> obj;

    static node null();
    static node str(std::string v);
    static node boolean(bool v);
    static node integer(int64_t v);
    static node array();
    static node map();

    node &add(node v);
    node &set(std::string key, node v);
    node &set(std::string key, std::string v);
    node &set(std::string key, const char *v);

    [[nodiscard]] bool is_null_like() const { return type == kind::null; }
    [[nodiscard]] bool is_map() const { return type == kind::map; }
    [[nodiscard]] bool is_array() const { return type == kind::array; }
    [[nodiscard]] bool is_string() const { return type == kind::string; }
};

struct node_kv {
    std::string first;
    node second;
};

inline node node::null() { return node{}; }
inline node node::str(std::string v)
{
    node n;
    n.type = kind::string;
    n.s = std::move(v);
    return n;
}
inline node node::boolean(bool v)
{
    node n;
    n.type = kind::boolean;
    n.b = v;
    return n;
}
inline node node::integer(int64_t v)
{
    node n;
    n.type = kind::integer;
    n.i = v;
    return n;
}
inline node node::array()
{
    node n;
    n.type = kind::array;
    return n;
}
inline node node::map()
{
    node n;
    n.type = kind::map;
    return n;
}
inline node &node::add(node v)
{
    arr.emplace_back(std::move(v));
    return arr.back();
}
inline node &node::set(std::string key, node v)
{
    obj.push_back({std::move(key), std::move(v)});
    return obj.back().second;
}
inline node &node::set(std::string key, std::string v) { return set(std::move(key), str(std::move(v))); }
inline node &node::set(std::string key, const char *v) { return set(std::move(key), str(v)); }

// Truncation applied by dd-trace-php (appsec/src/extension/msgpack_helpers.h)
// before anything reaches the WAF. A single budget is shared by query,
// cookies and body in request_init; headers and the response body get their
// own one.
struct php_limits {
    static constexpr std::size_t max_string_length = 4096;
    static constexpr unsigned max_depth = 21;
    std::size_t elements_remaining = 2048;
};

// Apply the limits in place (strings truncated, depth capped, containers cut
// once the element budget is exhausted). Mirrors dd_mpack_write_zval_lim.
void apply_limits(node &n, php_limits &lim, unsigned depth = 0);

// Convert to a ddwaf_object allocated with `alloc`.
void to_object(const node &n, ddwaf_object *out, ddwaf_allocator alloc);

// Serialise a node to JSON (used for request bodies' raw size estimation and
// debugging only).
std::string to_json(const node &n);

} // namespace bench
