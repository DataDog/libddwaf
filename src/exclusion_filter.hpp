// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <stack>
#include <vector>

#include <clock.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule.hpp>

namespace ddwaf {

template <typename T>
class path_trie {
public:
    path_trie() = default;

    path_trie find(const T &key) const {
        if (!root) { return {}; }
        auto it = root->values.find(key);
        if (it == root->values.end()) { return {}; }
        return path_trie<T>{it->second};
    }

    path_trie find(const std::vector<T> &path) const {
        if (!root) { return {}; }

        std::shared_ptr<trie_node> current = root;
        for (const auto &key : path) {
            auto it = current->values.find(key);
            if (it == current->values.end()) { return {}; }
            current = it->second;
        }
        return path_trie<T>{current};
    }

    template <typename U>
    void insert(const std::vector<U> &path) {
        if (!root) { root = std::make_shared<trie_node>(); }

        std::shared_ptr<trie_node> current = root;
        for (const auto &key : path) {
            auto it = current->values.find(key);
            if (it == current->values.end()) {
                const auto &[new_it, res] =
                    current->values.emplace(key, std::make_shared<trie_node>());
                current = new_it->second;
            } else {
                current = it->second;
            }
        }
    }

    bool is_valid() const { return root; }
    bool is_final() const { return root && root->values.empty(); }

protected:
    struct trie_node {
        std::unordered_map<T, std::shared_ptr<trie_node>> values;
    };

    explicit path_trie(std::shared_ptr<trie_node> node_): root(std::move(node_)) {}

    std::shared_ptr<trie_node> root;
};

class object_filter {
public:

    explicit object_filter(const std::unordered_set<std::vector<std::string>>& key_paths) {
        path_stack_.reserve(32);
        for (const auto &key_path: key_paths) {
            key_paths_.insert(key_path);
        }
    }

    bool push(unsigned) {
        // Currently array indices aren't supported as part of an object filter
        path_stack_.push_back({});
        return false;
    }

    bool push(std::string_view key) {
        path_stack_.push_back(path_stack_.back().find(key));
        return path_stack_.back().is_final();
    }

    void pop() {
        path_stack_.pop_back();
    }

    void reset() {
        path_stack_.clear();
    }
protected:
    std::vector<path_trie<std::string_view>> path_stack_;
    path_trie<std::string_view> key_paths_;
};

class exclusion_filter {
public:
    using ptr = std::shared_ptr<exclusion_filter>;

    struct input_set {
        void insert(manifest::target_type target) { targets_[target] = {}; }

        void insert(manifest::target_type target,
          std::vector<std::string> &&key_path) {
            auto it = targets_.find(target);
            if (it != targets_.end()) {
                if (it->second.empty()) {
                    return;
                }
                it->second.emplace(std::move(key_path));
            } else {
                targets_[target].emplace(std::move(key_path));
            }
        }

        [[nodiscard]] bool empty() const { return targets_.empty(); }

        std::unordered_map<manifest::target_type,
            std::unordered_set<std::vector<std::string>>> targets_;
    };

    struct cache_type {
        bool result{false};
        std::unordered_map<condition::ptr, bool> conditions;
    };

    exclusion_filter(std::vector<condition::ptr> &&conditions, std::set<rule::ptr> &&rule_targets,
      input_set && inputs)
        : conditions_(std::move(conditions)), rule_targets_(std::move(rule_targets)),
          inputs_(std::move(inputs))
    {}

    [[nodiscard]] const std::set<rule::ptr> &get_rule_targets() const { return rule_targets_; }
    [[nodiscard]] const input_set &get_inputs() const { return inputs_; }

    bool match(const object_store &store, const ddwaf::manifest &manifest, cache_type &cache,
        ddwaf::timer &deadline) const;

protected:
    std::vector<condition::ptr> conditions_;
    std::set<rule::ptr> rule_targets_;
    exclusion_filter::input_set inputs_;
};

} // namespace ddwaf
