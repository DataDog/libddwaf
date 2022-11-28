// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include<map>
#include <set>
#include <stack>
#include <vector>

#include <clock.hpp>
#include <manifest.hpp>
#include <object_store.hpp>

namespace ddwaf::exclusion {

class path_trie {
public:
    path_trie() = default;

    [[nodiscard]] path_trie find(std::string_view key) const;

    template <typename T>
    [[nodiscard]] path_trie find(const std::vector<T> &path) const;

    template <typename T>
    void insert(const std::vector<T> &path);

    [[nodiscard]] bool is_terminal() const { return root && root->terminal; }
    [[nodiscard]] bool is_valid() const { return root && !root->values.empty(); }

    [[nodiscard]] std::string debug() const;

protected:
    struct trie_node {
        // Heterogenous lookups required...
        // TODO: Change to unordered_map with C++20
        std::map<std::string, std::shared_ptr<trie_node>, std::less<>> values;
        bool terminal{false};
    };

    explicit path_trie(std::shared_ptr<trie_node> node_): root(std::move(node_)) {}

    std::shared_ptr<trie_node> root{nullptr};
};

class object_filter {
public:
    struct cache_type {
        std::unordered_set<manifest::target_type> inspected;
    };

    object_filter() = default;
    ~object_filter() = default;
    object_filter(const object_filter&) = default;
    object_filter(object_filter&&) = default;
    object_filter& operator=(const object_filter&) = default;
    object_filter& operator=(object_filter&&) = default;

    void insert(manifest::target_type target, const std::vector<std::string_view> &key_path) {
        target_paths_[target].insert(key_path);
    }

    std::unordered_set<ddwaf_object*> match(const object_store &store, ddwaf::timer &deadline) const;
protected:
    std::unordered_map<manifest::target_type, path_trie> target_paths_;
};

} // namespace ddwaf
