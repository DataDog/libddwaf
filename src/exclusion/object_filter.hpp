// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <ostream>
#include <set>
#include <stack>
#include <tuple>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "evaluation_cache.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "object_store.hpp"

namespace ddwaf {

class path_trie {
    class trie_node {
    public:
        trie_node() {} // NOLINT
        ~trie_node() = default;
        trie_node(const trie_node &) = delete;
        trie_node(trie_node &&) = default;
        trie_node &operator=(const trie_node &) = delete;
        trie_node &operator=(trie_node &&) = default;

        [[nodiscard]] const trie_node *get_child(std::string_view key) const
        {
            auto it = children_.find(key);
            if (it == children_.end()) {
                return nullptr;
            }
            return &it->second;
        }

        template <typename InternString>
        std::pair<std::reference_wrapper<trie_node>, bool /*is_new*/> get_or_create_child(
            std::string_view key, InternString &&intern_str_fun)
        {
            {
                auto it = children_.find(key);
                if (it != children_.end()) {
                    return {it->second, false};
                }
            }

            auto interned_str = std::forward<InternString>(intern_str_fun)(key);
            auto [it, is_new] = children_.emplace(std::piecewise_construct,
                std::forward_as_tuple(interned_str), std::forward_as_tuple());
            return {std::reference_wrapper{it->second}, true};
        }

        [[nodiscard]] bool is_terminal() const { return children_.empty(); }

        void clear() { children_.clear(); }

    protected:
#ifdef HAS_NONRECURSIVE_UNORDERED_MAP
        // unordered_map doesn't allow trie_node as the value of the map
        // because trie_node is an incomplete type at this point
        template <typename K, typename V> using MapType = std::map<K, V>;
#else
        template <typename K, typename V> using MapType = std::unordered_map<K, V>;
#endif
        MapType<std::string_view, trie_node> children_{};
    };
    static_assert(std::is_move_assignable_v<trie_node>);
    static_assert(std::is_move_constructible_v<trie_node>);
    static_assert(std::is_default_constructible_v<trie_node>);
    static_assert(std::is_constructible_v<trie_node>);

public:
    class traverser {
    public:
        enum class state : uint8_t { not_found, found, intermediate_node };

        explicit traverser(const trie_node *root)
        {
            if (root != nullptr) {
                cur_nodes_.emplace_back(root);
            }
        }

        [[nodiscard]] traverser descend(std::string_view next_key) const
        {
            if (get_state() != state::intermediate_node) {
                // once found/not_found, as we descend we keep the state
                return *this;
            }

            std::vector<const trie_node *> next_nodes;
            next_nodes.reserve(cur_nodes_.size());

            for (const auto *cur_node : cur_nodes_) {
                const auto *next_node = cur_node->get_child(next_key);
                if (next_node != nullptr) {
                    if (next_node->is_terminal()) {
                        return traverser{next_node};
                    }

                    next_nodes.emplace_back(next_node);
                }

                const auto *glob_node = cur_node->get_child("*");
                if (glob_node != nullptr) {
                    if (glob_node->is_terminal()) {
                        return traverser{glob_node};
                    }

                    next_nodes.emplace_back(glob_node);
                }
            }

            return traverser{std::move(next_nodes)};
        }

        [[nodiscard]] traverser descend_wildcard() const
        {
            if (get_state() != state::intermediate_node) {
                return *this;
            }

            std::vector<const trie_node *> next_nodes;
            next_nodes.reserve(cur_nodes_.size());

            for (const auto *cur_node : cur_nodes_) {
                const auto *glob_node = cur_node->get_child("*");
                if (glob_node != nullptr) {
                    if (glob_node->is_terminal()) {
                        return traverser{glob_node};
                    }

                    next_nodes.emplace_back(glob_node);
                }
            }

            return traverser{std::move(next_nodes)};
        }

        [[nodiscard]] state get_state() const
        {
            if (cur_nodes_.empty()) {
                return state::not_found;
            }

            if (cur_nodes_.size() == 1 && cur_nodes_.back()->is_terminal()) {
                return state::found;
            }

            return state::intermediate_node;
        }

    private:
        explicit traverser(std::vector<const trie_node *> &&nodes) : cur_nodes_(std::move(nodes)) {}
        std::vector<const trie_node *> cur_nodes_;
    };

    template <typename StringType>
    void insert(const std::vector<StringType> &path)
        requires std::is_constructible_v<std::string_view, StringType>
    {
        if (!root) {
            root.emplace();
        }

        trie_node *cur = &root.value();
        // default is true because if the path is empty,
        // we should clear all the children (trie includes all possible paths)
        bool last_is_new = true;
        for (auto &&component : path) {
            auto &&[node, is_new] = cur->get_or_create_child(
                component, [this](std::string_view sv) { return intern_string(sv); });
            if (!is_new && node.get().is_terminal()) {
                // we're inserting a subpath for a path that already exists
                return;
            }
            cur = &node.get();
            last_is_new = is_new;
        }
        if (!last_is_new) {
            // already existed. If it had children, make it a terminal node
            cur->clear();
        }
    }

    [[nodiscard]] traverser get_traverser() const
    {
        if (!root) {
            return traverser{nullptr};
        }
        return traverser{&root.value()};
    }

private:
    std::string_view intern_string(std::string_view orig_sv)
    {
        auto it = strings.find(orig_sv);
        if (it != strings.end()) {
            return {*it};
        }

        auto [new_it, is_new] = strings.emplace(orig_sv);
        return {*new_it};
    }

    // we allow adding the root to the trie (matching everything)
    // so we use an optional to distinguish the two cases (empty vs everything)
    std::optional<trie_node> root = std::nullopt;
    std::set<std::string, std::less<>> strings;
};

inline std::ostream &operator<<(std::ostream &os, const path_trie::traverser::state &st)
{
    using state = path_trie::traverser::state;
    switch (st) {
    case state::not_found:
        return os << std::string_view{"not_found"};
    case state::found:
        return os << std::string_view{"found"};
    case state::intermediate_node:
        return os << std::string_view{"intermediate_node"};
    }
    // Suppress warning
    return os;
}

class object_filter {
public:
    struct cached_object_and_scope {
        object_cache_key object;
        evaluation_scope scope;
    };

    // cache_type will always be limited by target_paths_.size(), so it can use
    // the context allocator
    using cache_type = cache_entry<memory::unordered_map<target_index, cached_object_and_scope>>;
    using base_cache_type = cache_type::base_type;

    object_filter() = default;

    void insert(
        target_index target, std::string name, const std::vector<std::string_view> &key_path = {})
    {
        target_paths_[target].insert(key_path);
        targets_.emplace(target, std::move(name));
    }

    [[nodiscard]] bool empty() const { return target_paths_.empty(); }

    object_set match(const object_store &store, base_cache_type &cache, evaluation_scope scope,
        ddwaf::timer &deadline) const;

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        for (const auto &[index, str] : targets_) { addresses.emplace(index, str); }
    }

protected:
    std::unordered_map<target_index, path_trie> target_paths_;
    std::unordered_map<target_index, std::string> targets_;
};

} // namespace ddwaf
