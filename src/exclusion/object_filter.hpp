// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <clock.hpp>
#include <config.hpp>
#include <functional>
#include <list>
#include <log.hpp>
#include <manifest.hpp>
#include <map>
#include <object_store.hpp>
#include <ostream>
#include <set>
#include <stack>
#include <tuple>
#include <type_traits>
#include <unordered_set>
#include <vector>

namespace ddwaf::exclusion {

class path_trie {
public:
    struct path {
        explicit path(std::string_view component) noexcept : component{component} {}
        path(path *prev, std::string_view component) noexcept : component{component}, prev{prev} {}

        std::string_view component;
        path *prev{};
        // for tracking when we can dispose of the object
        // we iterate depth-first, first nodes last
        bool first_child{};

        [[nodiscard]] bool is_nameless() const noexcept { return component.empty(); }
    };

private:
    class trie_node {
    public:
        trie_node() {} // NOLINT
        ~trie_node() = default;
        trie_node(const trie_node &) = delete;
        trie_node(trie_node &&) = default;
        trie_node &operator=(const trie_node &) = delete;
        trie_node &operator=(trie_node &&) = default;

        [[nodiscard]] trie_node const *get_child(std::string_view key) const
        {
            auto it = children.find(key);
            if (it == children.end()) {
                return nullptr;
            }
            return &it->second;
        }

        template <typename InternString>
        std::pair<std::reference_wrapper<trie_node>, bool /*is_new*/> get_or_create_child(
            std::string_view key, InternString &&intern_str_fun)
        {
            {
                auto it = children.find(key);
                if (it != children.end()) {
                    return {it->second, false};
                }
            }

            auto interned_str = std::forward<InternString>(intern_str_fun)(key);
            auto [it, is_new] = children.emplace(std::piecewise_construct,
                std::forward_as_tuple(interned_str), std::forward_as_tuple());
            return {std::reference_wrapper{it->second}, true};
        }

        [[nodiscard]] bool is_terminal() const { return children.empty(); }

#ifdef HAS_NONRECURSIVE_UNORDERED_MAP
        // unordered_map doesn't allow trie_node as the value of the map
        // because trie_node is an incomplete type at this point
        template <typename K, typename V> using MapType = std::map<K, V>;
#else
        template <typename K, typename V> using MapType = std::unordered_map<K, V>;
#endif
        MapType<std::string_view, trie_node> children{};
    };
    static_assert(std::is_move_assignable_v<trie_node>);
    static_assert(std::is_move_constructible_v<trie_node>);
    static_assert(std::is_default_constructible_v<trie_node>);
    static_assert(std::is_constructible_v<trie_node>);

public:
    class traverser {
        struct backtrack_info {
            backtrack_info(const trie_node *alternative_node, const path *path)
                : alternative_node{alternative_node}, path{path}
            {}
            const trie_node *alternative_node;
            const path *path;
        };

    public:
        enum class state { not_found, found, intermediate_node };

        explicit traverser(trie_node const *root) : cur_node{root} {}
        traverser(trie_node const *root, std::stack<backtrack_info> btinfo)
            : cur_node{root}, backtrack_data{std::move(btinfo)}
        {}

        [[nodiscard]] bool can_backtrack() const { return !backtrack_data.empty(); }

        // descend only on the final component
        [[nodiscard]] traverser descend(const path *p) const // NOLINT(misc-no-recursion)
        {
            if (get_state() != state::intermediate_node) {
                // once found/not_found, as we descend we keep the state
                return traverser{cur_node};
            }
            auto next_key = p->component;

            const auto *glob_node = cur_node->get_child("*");
            const auto *next_node = p->is_nameless() ? nullptr : cur_node->get_child(next_key);

            // exactly one node available
            if (glob_node != nullptr && next_node == nullptr) {
                return traverser{glob_node, backtrack_data};
            }
            if (next_node != nullptr && glob_node == nullptr) {
                return traverser{next_node, backtrack_data};
            }
            // both nodes unavailable
            if (glob_node == nullptr && next_node == nullptr) {
                if (can_backtrack()) {
                    return backtrack_and_move(p);
                }
                return traverser{nullptr}; // not found
            }
            // both nodes available
            auto bt_data = backtrack_data;
            bt_data.emplace(next_node, p);
            return traverser{glob_node, std::move(bt_data)};
        }

        [[nodiscard]] state get_state() const
        {
            if (cur_node == nullptr) {
                return state::not_found;
            }
            return cur_node->is_terminal() ? state::found : state::intermediate_node;
        }

    private:
        // NOLINTNEXTLINE(misc-no-recursion)
        [[nodiscard]] traverser backtrack_and_move(const path *p) const
        {
            traverser cur_traverser = *this;
            while (cur_traverser.can_backtrack()) {
                auto bt_data_stack = cur_traverser.backtrack_data;
                const backtrack_info &bt_info = bt_data_stack.top();
                bt_data_stack.pop();
                cur_traverser =
                    traverser{bt_info.alternative_node, std::move(bt_data_stack)};
                auto components = components_between(bt_info.path, p);
                while (cur_traverser.get_state() == state::intermediate_node) {
                    const auto *comp = components.top();
                    components.pop();
                    cur_traverser = cur_traverser.descend(comp);
                }
                if (cur_traverser.get_state() != state::not_found) {
                    return cur_traverser;
                }
            }
            return traverser{nullptr};
        }

        static std::stack<const path *> components_between(
            // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
            const path *start_excl, const path *end_incl)
        {
            std::stack<const path *> ret;
            for (const auto *p = end_incl; p != start_excl; p = p->prev) { ret.push(p); }
            return ret;
        }

        trie_node const *cur_node{};
        std::stack<backtrack_info> backtrack_data{};
    };

    template <typename StringType,
        typename = std::enable_if<std::is_constructible<std::string, StringType>::value>>
    void insert(const std::vector<StringType> &path)
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
            cur->children.clear();
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
