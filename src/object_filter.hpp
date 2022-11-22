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
#include <input_filter.hpp>
#include <manifest.hpp>
#include <object_store.hpp>

namespace ddwaf {

template <typename T>
class path_trie {
public:
    path_trie() = default;

    [[nodiscard]] path_trie find(const T &key) const {
        if (!root) { return {}; }
        auto it = root->values.find(key);
        if (it == root->values.end()) { return {}; }
        return path_trie<T>{it->second};
    }

    [[nodiscard]] path_trie find(const std::vector<T> &path) const {
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

    [[nodiscard]] bool is_valid() const { return root; }
    [[nodiscard]] bool is_final() const { return root && root->values.empty(); }

protected:
    struct trie_node {
        std::unordered_map<T, std::shared_ptr<trie_node>> values;
    };

    explicit path_trie(std::shared_ptr<trie_node> node_): root(std::move(node_)) {}

    std::shared_ptr<trie_node> root;
};

class object_filter_base {
public:
    object_filter_base() = default;
    object_filter_base(const object_filter_base&) = default;
    object_filter_base(object_filter_base&&) = default;
    object_filter_base &operator=(const object_filter_base&) = default;
    object_filter_base &operator=(object_filter_base&&) = default;

    virtual ~object_filter_base() = default;
    virtual bool push(unsigned  /*index*/) = 0;
    virtual bool push(std::string_view key) = 0;
    virtual void pop() = 0;
    virtual void reset() = 0;
};

class nop_object_filter : public object_filter_base {
    bool push(unsigned  /*index*/) override {
        return false;
    }

    bool push(std::string_view  /*key*/) override {
        return false;
    }

    void pop() override {}
    void reset() override {}
};

class object_filter : public object_filter_base {
public:
    explicit object_filter(const std::unordered_set<std::vector<std::string>>& key_paths) {
        path_stack_.reserve(initial_stack_size);
        for (const auto &key_path: key_paths) {
            key_paths_.insert(key_path);
        }
    }

    bool push(unsigned  /*index*/) override {
        // Currently array indices aren't supported as part of an object filter
        path_stack_.emplace_back();
        return false;
    }

    bool push(std::string_view key) override {
        path_stack_.push_back(path_stack_.back().find(key));
        return path_stack_.back().is_final();
    }

    void pop() override {
        path_stack_.pop_back();
    }

    void reset() override {
        path_stack_.clear();
    }
protected:
    static constexpr unsigned initial_stack_size = 32;
    std::vector<path_trie<std::string_view>> path_stack_;
    path_trie<std::string_view> key_paths_;
};

} // namespace ddwaf
