// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <map>
#include <set>
#include <stack>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <clock.hpp>
#include <config.hpp>
#include <log.hpp>
#include <manifest.hpp>
#include <object_store.hpp>

namespace ddwaf::exclusion {

class path_trie {
private:
    struct trie_node {
        std::string path_component;
        std::vector<trie_node> children{};

        explicit trie_node(std::string path_component) :
            path_component{std::move(path_component)} {}

        ~trie_node() = default;
        trie_node(const trie_node&) = delete;
        trie_node(trie_node&&) = default;
        trie_node& operator=(const trie_node&) = delete;
        trie_node& operator=(trie_node&&) = default;

        struct comp {
            bool operator()(const trie_node& n, std::string_view v) {
                return std::string_view{n.path_component} < v;
            }
            bool operator()(std::string_view v, const trie_node& n) {
                return v < std::string_view{n.path_component};
            }
        };

        [[nodiscard]] trie_node const *get_child(std::string_view key) const {
            auto [beg, end] = std::equal_range(
                children.begin(), children.end(), key, comp{});
            if (beg != end) {
                return &*beg;
            }
            return nullptr;
        }

        trie_node& get_or_create_child(std::string_view key, bool& is_new) {
            auto [beg, end] = std::equal_range(
                children.begin(), children.end(), key, comp{});
            if (beg != end) {
                is_new = false;
                return *beg;
            }

            auto ins_it = children.emplace(end, std::string{key});
            is_new = true;
            return *ins_it;
        }

        [[nodiscard]] bool is_terminal() const {
            return children.empty();
        }
    };
    static_assert(std::is_move_assignable<trie_node>::value);

    trie_node root{""};
    // we allow adding the root to the trie (matching everything)
    // so we use this flag to distinguish the two cases (empty vs everything)
    bool is_empty{true}; 

public:
    class traverser {
        trie_node const *const cur_node{};
    public:    
        enum class state {
            NOT_FOUND,
            FOUND,
            GLUE
        };

        explicit traverser(trie_node const *root) : cur_node{root} {}
        [[nodiscard]] traverser descend(std::string_view next_key) const {
            if (get_state() != state::GLUE) {
                // once FOUND/NOT_FOUND, as we descend we keep the state
                return *this;
            }
            return traverser{cur_node->get_child(next_key)};
        }
        [[nodiscard]] state get_state() const {
            if (cur_node == nullptr) {
                return state::NOT_FOUND;
            }
            return cur_node->is_terminal() ? state::FOUND : state::GLUE;
        }
    };

    template <typename StringType,
        typename = std::enable_if<std::is_constructible<std::string, StringType>::value>>
    void insert(const std::vector<StringType> &path)
    {
        is_empty = false;

        trie_node *cur = &root;
        bool is_new;
        for (auto&& component: path) {
            auto &&node = cur->get_or_create_child(component, is_new);
            if (!is_new && node.is_terminal()) {
                // we're inserting a subpath for a path that already exists
                return;
            }
            cur = &node;
        }
        if (!is_new) {
            // already existed. If it had children, make it a terminal node
            cur->children.clear();
        }
    }

    [[nodiscard]] traverser get_traverser() const {
        if (is_empty) {
            return traverser{nullptr};
        }
        return traverser{&root};
    }
};

inline std::ostream &operator<<(std::ostream &os, const path_trie::traverser::state &st)
{
    using state = path_trie::traverser::state;
    switch (st) {
        case state::NOT_FOUND:
        return os << std::string_view{"NOT_FOUND"};
        case state::FOUND:
        return os << std::string_view{"FOUND"};
        case state::GLUE:
        return os << std::string_view{"GLUE"};
    }
}

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
