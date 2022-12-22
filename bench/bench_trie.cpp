#include <benchmark/benchmark.h>
#include <exception>
#include <list>
#include <optional>
#include <stack>
#include <unistd.h>
#include <unordered_map>
#include <iostream>
#include <type_traits>
#include <experimental/memory_resource>

namespace curimpl {
class path_trie {
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
        enum class state { not_found, found, intermediate_node };

        explicit traverser(trie_node const *root)
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
} // namespace curimpl

namespace proposedimpl1 {
class path_trie {
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
    public:
        enum class state { not_found, found, intermediate_node };

        explicit traverser(trie_node const *root) : cur_node{root} {}

        traverser(trie_node const *root, std::list<std::pair<trie_node const *, unsigned>> &&globs,
            std::vector<std::string_view> &&stack)
            : cur_node{root}, seen_globs(std::move(globs)), key_stack(std::move(stack))
        {}

        static const trie_node *backtrack(std::string_view next_key,
            const std::vector<std::string_view> &stack,
            std::list<std::pair<const trie_node *, unsigned>> &globs)
        {
            // We have reached this point with a null node, which means
            // there is no glob node available, but we still have previously
            // seen globs, so we backtrack
            for (auto it = globs.begin(); it != globs.end();) {
                const trie_node *root = it->first;
                for (auto i = it->second; root != nullptr && i < stack.size(); i++) {
                    root = root->get_child(stack[i]);
                }
                // XXX: orig code
                // root = root->get_child(next_key);
                if (root != nullptr) {
                    root = root->get_child(next_key);
                }

                // We remove the glob from the list as we're either following it
                // or it's not a valid path
                it = globs.erase(it);

                if (root != nullptr) {
                    return root;
                }
            }

            return nullptr;
        }

        [[nodiscard]] traverser descend_wildcard() const
        {
            if (get_state() != state::intermediate_node) {
                // once found/not_found, as we descend we keep the state
                return *this;
            }

            const auto *next_node = cur_node->get_child("*");
            if (next_node == nullptr && seen_globs.empty()) {
                return traverser{nullptr};
            }

            auto globs = seen_globs;
            if (next_node == nullptr) {
                next_node = backtrack("*", key_stack, globs);
            }

            if (next_node == nullptr || globs.empty()) {
                return traverser{next_node};
            }

            auto new_stack = key_stack;
            new_stack.emplace_back("*");
            return {next_node, std::move(globs), std::move(new_stack)};
        }

        [[nodiscard]] traverser descend(std::string_view next_key) const
        {
            if (get_state() != state::intermediate_node) {
                // once found/not_found, as we descend we keep the state
                return *this;
            }

            const auto *glob_node = cur_node->get_child("*");
            const auto *next_node = cur_node->get_child(next_key);
            if (next_node == nullptr) {
                if (glob_node == nullptr && seen_globs.empty()) {
                    return traverser{nullptr};
                }
                next_node = glob_node;
            }

            auto globs = seen_globs;
            if (next_node == nullptr) {
                next_node = backtrack(next_key, key_stack, globs);
            } else {
                // Find the next glob, the depth should be current + 1
                if (glob_node != nullptr && glob_node != next_node) {
                    globs.emplace_front(glob_node, key_stack.size() + 1);
                }
            }

            if (next_node == nullptr || globs.empty()) {
                return traverser{next_node};
            }

            auto new_stack = key_stack;
            new_stack.emplace_back(next_key);

            return {next_node, std::move(globs), std::move(new_stack)};
        }

        [[nodiscard]] state get_state() const
        {
            if (cur_node == nullptr) {
                return state::not_found;
            }
            return cur_node->is_terminal() ? state::found : state::intermediate_node;
        }

    private:
        trie_node const *cur_node{};
        std::list<std::pair<trie_node const *, unsigned>> seen_globs{};
        std::vector<std::string_view> key_stack{};
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
} // namespace proposedimpl1

namespace proposedimpl2 {
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
                assert(!components.empty()); // NOLINT
                while (!components.empty() && cur_traverser.get_state() == state::intermediate_node) {
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

} // namespace proposedimpl2

struct Fixture  {
    curimpl::path_trie cur_trie;
    proposedimpl1::path_trie proposed_trie1;
    proposedimpl2::path_trie proposed_trie2;

    std::vector<std::vector<std::string>> all_paths;
    int64_t last_depth{}, last_breadth{}, last_str_len{};

    void SetUp(const ::benchmark::State &state)
    {
        int64_t depth = state.range(0);
        int64_t breadth = state.range(1);
        int64_t str_len = state.range(2);
        int64_t wildcard_period = 3; // NOLINT
        if (depth == last_depth && breadth == last_breadth && str_len == last_str_len) {
            return;
        }
        last_depth = depth;
        last_breadth = breadth;
        last_str_len = str_len;

        all_paths.clear();
        cur_trie = decltype(cur_trie){};
        proposed_trie1 = decltype(proposed_trie1){};
        proposed_trie2 = decltype(proposed_trie2){};

        all_paths.reserve(static_cast<int64_t>(pow(breadth, depth)));

        std::vector<std::vector<std::string>> strings_per_level;
        strings_per_level.reserve(depth);
        for (int64_t i = 0; i < depth; i++) {
            std::vector<std::string> level_strings;
            level_strings.reserve(breadth);
            for (int64_t j = 0; j < breadth; j++) {
                level_strings.emplace_back(gen_str(str_len));
            }
            strings_per_level.emplace_back(level_strings);
        }

        std::vector<int64_t> key;
        for (int64_t i = 0; i < depth; i++) { key.push_back(0); }

        while (true) {
            std::vector<std::string> cur;
            cur.reserve(depth);
            for (int64_t i = 0; i < depth; i++) {
                cur.push_back(strings_per_level[i][key[i]]);
            }
            all_paths.push_back(cur);
            // update key
            for (int64_t i = depth - 1; i >= 0; i--) {
                int64_t c = key[i];
                if (c == breadth - 1) {
                    key[i] = 0;
                } else {
                    key[i]++;
                    break;
                }
                if (i == 0) {
                    goto end;
                }
            }
        }
    end:
        int64_t counter{0LL};
        for (auto&& p: all_paths) {
            if (counter++ % wildcard_period != 0) {
                cur_trie.insert(p);
                proposed_trie1.insert(p);
                proposed_trie2.insert(p);
            } else {
                std::vector<std::string> pcopy{p};
                auto replacement_pos = counter % pcopy.size();
                pcopy[replacement_pos] = "*";

                cur_trie.insert(pcopy);
                proposed_trie1.insert(pcopy);
                proposed_trie2.insert(pcopy);
            }
        }

        // std::cerr << "Initialized tries with " << all_paths.size() <<
        // " elements (depth " << depth << ", breadth " << breadth << ")\n";
    }

private:
    static std::string gen_str(size_t len) {
        // NOLINTNEXTLINE
        static constexpr char alphanum[] = "0123456789"
                                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                           "abcdefghijklmnopqrstuvwxyz";
        std::string tmp_s;
        tmp_s.reserve(len);

        // NOLINTNEXTLINE
        for (size_t i = 0; i < len; ++i) { tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)]; }
        return tmp_s;
    }
};

// NOLINTNEXTLINE
static Fixture f;

// NOLINTNEXTLINE
static void bm_cur_trie(benchmark::State& state) {
    while (state.KeepRunning()) {
        auto &&p = f.all_paths[rand() % f.all_paths.size()]; // NOLINT
        auto it = f.cur_trie.get_traverser();
        for (auto &&pc : p) { it = it.descend(pc); }
        if (it.get_state() != curimpl::path_trie::traverser::state::found) {
            throw std::runtime_error{"bad result"};
        }
    }
}

static void bm_proposed1(benchmark::State& state) {
    while (state.KeepRunning()) {
        auto &&p = f.all_paths[rand() % f.all_paths.size()]; // NOLINT

        auto it = f.proposed_trie1.get_traverser();
        for (auto &&pc : p) { it = it.descend(pc); }
        if (it.get_state() != proposedimpl1::path_trie::traverser::state::found) {
            throw std::runtime_error{"bad result"};
        }
    }
}

static void bm_proposed2(benchmark::State& state) {
    std::unique_ptr<char[]> memory_buffer{new char[524288]}; // NOLINT
    while (state.KeepRunning()) {
        auto &&p = f.all_paths[rand() % f.all_paths.size()]; // NOLINT
        auto it = f.proposed_trie2.get_traverser();
        size_t mempos = 0;
        using path = proposedimpl2::path_trie::path;
        path *cpath{nullptr};
        for (auto &&pc : p) {
            cpath = new(&memory_buffer[mempos]) path{cpath, pc};
            mempos += sizeof(*cpath);
            it = it.descend(cpath);
        }
        if (it.get_state() != proposedimpl2::path_trie::traverser::state::found) {
            throw std::runtime_error{"bad result"};
        }
    }
}

// NOLINTNEXTLINE
BENCHMARK(bm_cur_trie)->Ranges({{2,4}, {2,16}, {8, 8}})->Setup(
    [](auto &state) { f.SetUp(state); });
// NOLINTNEXTLINE
BENCHMARK(bm_proposed1)->Ranges({{2, 4}, {2,16}, {8, 8}})->Setup(
    [](auto &state) { f.SetUp(state); });
// NOLINTNEXTLINE
BENCHMARK(bm_proposed2)->Ranges({{2,4}, {2,16}, {8, 8}})->Setup(
    [](auto &state) { f.SetUp(state); });
BENCHMARK_MAIN(); // NOLINT
