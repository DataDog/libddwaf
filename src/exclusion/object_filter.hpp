// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <map>
#include <set>
#include <stack>
#include <vector>

#include <clock.hpp>
#include <config.hpp>
#include <log.hpp>
#include <manifest.hpp>
#include <object_store.hpp>

namespace ddwaf::exclusion {

class path_trie {
public:
    path_trie() = default;

    [[nodiscard]] path_trie find(std::string_view key) const;

    template <typename T> [[nodiscard]] path_trie find(const std::vector<T> &path) const;

    template <typename T> void insert(const std::vector<T> &path);

    [[nodiscard]] bool is_terminal() const { return root && root->terminal; }
    [[nodiscard]] bool is_valid() const { return root && !root->values.empty(); }

protected:
    struct trie_node {
        // Heterogenous lookups required...
        // TODO: Change to unordered_map with C++20
        std::map<std::string, std::shared_ptr<trie_node>, std::less<>> values;
        // TODO this shouldn't be necessary
        bool terminal{false};
    };

    explicit path_trie(std::shared_ptr<trie_node> node_) : root(std::move(node_)) {}

    std::shared_ptr<trie_node> root{nullptr};
};

class object_filter {
public:
    using cache_type = std::unordered_set<manifest::target_type>;

    explicit object_filter(const ddwaf::object_limits &limits = {}) : limits_(limits) {}

    void insert(manifest::target_type target, const std::vector<std::string_view> &key_path = {})
    {
        target_paths_[target].insert(key_path);
    }

    std::unordered_set<const ddwaf_object *> match(
        const object_store &store, cache_type &cache, ddwaf::timer &deadline) const;

protected:
    object_limits limits_;
    std::unordered_map<manifest::target_type, path_trie> target_paths_;
};

} // namespace ddwaf::exclusion
