// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "matcher/regex_prefilter.hpp"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/util/utf.h"

namespace ddwaf::matcher {

namespace {

using re2::Regexp;
using re2::Rune;

// Exact sets larger than this are turned into disjunctions of atoms
constexpr std::size_t max_exact_strings = 16;
// Character classes with more characters than this are treated as wildcards
constexpr int max_class_characters = 4;
// Formulas nested deeper than this are replaced by "anything matches"
constexpr unsigned max_formula_depth = 32;
constexpr std::size_t max_formula_atoms = 4096;
constexpr unsigned max_analysis_steps = 1000;
// Expressions anchored at the beginning of the input are rejected by RE2 after
// a few characters, so they benefit less from prefiltering and get a smaller
// analysis budget
constexpr unsigned max_anchored_analysis_steps = 200;
// Bounds the stack usage of the analysis
constexpr unsigned max_analysis_depth = 64;

// Returns the lowercase ASCII character which stands for the given character
// in atoms, or -1 if the character can't be part of an atom.
int atom_character(Rune r)
{
    if (r < 0x80) {
        return (r >= 'A' && r <= 'Z') ? r + ('a' - 'A') : r;
    }
    // The only non-ASCII characters in the case-folding orbit of an ASCII
    // character; inputs containing them bypass the prefilter, so they can
    // stand for their ASCII counterpart here.
    if (r == 0x017F) { // LATIN SMALL LETTER LONG S
        return 's';
    }
    if (r == 0x212A) { // KELVIN SIGN
        return 'k';
    }
    return -1;
}

// The strings of the analysis are immutable and allocated from the memory
// resource of the analysis, like all its containers
using string_set = std::pmr::vector<std::string_view>;

// Allocates the concatenation of two strings from a memory resource
std::string_view concatenate(
    std::pmr::memory_resource *mr, std::string_view first, std::string_view second = {})
{
    // The strings are immutable and live as long as the analysis, so they
    // can be shared
    if (first.empty()) {
        return second;
    }
    if (second.empty()) {
        return first;
    }

    const auto size = first.size() + second.size();
    auto *buffer = static_cast<char *>(mr->allocate(size, 1));
    std::memcpy(buffer, first.data(), first.size());
    std::memcpy(buffer + first.size(), second.data(), second.size());
    return {buffer, size};
}

// Strings of one character, which don't need to be allocated
constexpr auto single_characters = []() {
    std::array<char, 128> characters{};
    for (std::size_t i = 0; i < characters.size(); ++i) { characters[i] = static_cast<char>(i); }
    return characters;
}();

std::string_view single_character(int c)
{
    return {&single_characters[static_cast<std::size_t>(c)], 1};
}

void normalise(string_set &strings)
{
    if (strings.size() <= 1) {
        return;
    }
    std::sort(strings.begin(), strings.end());
    strings.erase(std::unique(strings.begin(), strings.end()), strings.end());
}

// Monotone boolean formulas over atoms, stored in an arena. A formula is a
// handle to a node; since a formula is only ever used once, to build a larger
// one, nodes are combined in place rather than copied.
class formula_arena {
public:
    explicit formula_arena(std::pmr::memory_resource *mr) : nodes_(mr), atoms_(mr) {}

    using handle = uint32_t;
    enum class kind : uint8_t { atom, conjunction, disjunction };

    // Always true and never true, respectively
    static constexpr handle all = std::numeric_limits<handle>::max();
    static constexpr handle none = all - 1;

    struct node {
        kind type;
        uint8_t depth;
        // Atom: index of the string; operation: first and last operands
        handle first;
        handle last;
        // Next operand of the enclosing operation
        handle next;
    };

    handle atom(std::string_view str)
    {
        const auto index = static_cast<handle>(atoms_.size());
        atoms_.emplace_back(str);
        return add_node(
            {.type = kind::atom, .depth = 0, .first = index, .last = index, .next = all});
    }

    // Combines two formulas with a conjunction or a disjunction, simplifying
    // the trivial cases and flattening nested operations of the same kind.
    handle combine(kind op, handle a, handle b)
    {
        const handle identity = op == kind::conjunction ? all : none;
        const handle absorbing = op == kind::conjunction ? none : all;

        if (a == absorbing || b == absorbing) {
            return absorbing;
        }

        if (a == identity) {
            return b;
        }

        if (b == identity) {
            return a;
        }

        handle result = a;
        if (nodes_[a].type != op) {
            result = add_node({.type = op,
                .depth = static_cast<uint8_t>(nodes_[a].depth + 1),
                .first = a,
                .last = a,
                .next = all});
        }

        auto &r = nodes_[result];
        unsigned depth = r.depth;
        if (nodes_[b].type == op) {
            nodes_[r.last].next = nodes_[b].first;
            r.last = nodes_[b].last;
            depth = std::max<unsigned>(depth, nodes_[b].depth);
        } else {
            nodes_[r.last].next = b;
            r.last = b;
            depth = std::max<unsigned>(depth, nodes_[b].depth + 1);
        }

        if (depth > max_formula_depth) {
            // This is always a valid (if useless) necessary condition
            return all;
        }
        r.depth = static_cast<uint8_t>(depth);

        return result;
    }

    // Disjunction of atoms: some string of the set is present
    handle disjunction_of(const string_set &strings)
    {
        if (strings.empty()) {
            return none;
        }

        for (const auto &str : strings) {
            // A short atom is not worth searching for (and "" is always present)
            if (str.size() < regex_prefilter::min_atom_length) {
                return all;
            }
        }

        // The strings of an exact set are unique, there's nothing to simplify
        handle result = none;
        for (auto str : strings) { result = combine(kind::disjunction, result, atom(str)); }
        return result;
    }

    [[nodiscard]] const node &operator[](handle h) const { return nodes_[h]; }
    [[nodiscard]] std::string_view atom_of(handle h) const { return atoms_[nodes_[h].first]; }
    [[nodiscard]] std::size_t atom_count() const { return atoms_.size(); }

protected:
    handle add_node(node n)
    {
        nodes_.emplace_back(n);
        return static_cast<handle>(nodes_.size() - 1);
    }

    std::pmr::vector<node> nodes_;
    string_set atoms_;
};

using kind = formula_arena::kind;
using handle = formula_arena::handle;

// What is known about the strings matched by a subexpression, lowercased:
// each of them is either one of a small exact set of strings, or satisfies a
// formula. A purely exact subexpression has a "none" formula, one about which
// nothing is known has an "all" formula.
//
// Keeping the exact strings apart from the formula allows them to be extended
// by what follows, as in `(?:inexact|fi)le`, which requires "file" or the
// formula of `inexact`.
// NOLINTNEXTLINE(bugprone-exception-escape)
struct info {
    string_set strings; // sorted and unique
    handle match{formula_arena::none};

    explicit info(std::pmr::memory_resource *mr) : strings(mr) {}
    info(string_set &&strs, handle f) : strings(std::move(strs)), match(f) {}

    static info exact_set(string_set strings)
    {
        normalise(strings);
        return {std::move(strings), formula_arena::none};
    }

    static info empty_string(std::pmr::memory_resource *mr)
    {
        string_set strings{mr};
        strings.emplace_back();
        return {std::move(strings), formula_arena::none};
    }
    static info nothing(std::pmr::memory_resource *mr) { return info{mr}; }
    static info anything(std::pmr::memory_resource *mr)
    {
        return from_formula(mr, formula_arena::all);
    }

    static info from_formula(std::pmr::memory_resource *mr, handle f)
    {
        info i{mr};
        i.match = f;
        return i;
    }

    [[nodiscard]] bool is_exact() const { return match == formula_arena::none; }
    [[nodiscard]] bool is_anything() const { return match == formula_arena::all; }
};

string_set cross_product(const string_set &prefixes, const string_set &suffixes)
{
    auto *mr = prefixes.get_allocator().resource();
    string_set product{mr};
    product.reserve(prefixes.size() * suffixes.size());
    for (auto prefix : prefixes) {
        for (auto suffix : suffixes) { product.emplace_back(concatenate(mr, prefix, suffix)); }
    }
    // A single prefix keeps the suffixes sorted and unique
    if (prefixes.size() > 1) {
        normalise(product);
    }
    return product;
}

// Computes the info of a regular expression. The recursion is bounded by
// max_analysis_depth, and the number of subexpressions visited by
// max_analysis_steps: past either, the analysis fails and the expression is
// not prefiltered.
class analyser {
public:
    analyser(std::pmr::memory_resource *mr, unsigned max_steps)
        : mr_(mr), arena_(mr), max_steps_(max_steps)
    {}

    // Returns the formula of the regular expression, or nullopt if the
    // analysis failed
    std::optional<handle> analyse(Regexp *re)
    {
        auto result = visit(re, 0);
        if (failed_) {
            return std::nullopt;
        }
        return take_match(result);
    }

    [[nodiscard]] const formula_arena &arena() const { return arena_; }

protected:
    // Concatenation: the exact strings of consecutive subexpressions are
    // combined into their cross product as long as it stays small, the rest
    // becomes a conjunction of what is known about each part.
    class concatenation {
    public:
        explicit concatenation(analyser &a) : analyser_(a), current_(a.mr_) {}

        void add(info &&next)
        {
            if (!has_current_) {
                current_ = std::move(next);
                has_current_ = true;
                return;
            }

            auto &arena = analyser_.arena_;

            // With x matched by current_ and y by next, xy is either one of
            // the cross product of their exact strings, or satisfies:
            //   (current_.match(x) && (y in next.strings || next.match(y)))
            //       || (x in current_.strings && next.match(y))
            // which is only kept when one of the two formulas is "none"
            // (exact); otherwise, or if the cross product is too large, what
            // is known about current_ is moved to the conjunction and next
            // starts a new run.
            if (current_.strings.empty() ||
                current_.strings.size() * next.strings.size() > max_exact_strings ||
                (!current_.is_exact() && !next.is_exact())) {
                conjunction_ =
                    arena.combine(kind::conjunction, conjunction_, analyser_.take_match(current_));
                current_ = std::move(next);
                flushed_ = true;
                return;
            }

            info result{analyser_.mr_};
            if (!current_.is_exact()) {
                result.match = arena.combine(
                    kind::conjunction, current_.match, arena.disjunction_of(next.strings));
            } else if (!next.is_exact()) {
                result.match = arena.combine(
                    kind::conjunction, arena.disjunction_of(current_.strings), next.match);
            }
            if (!result.is_anything()) {
                result.strings = cross_product(current_.strings, next.strings);
            }
            current_ = std::move(result);
        }

        info finish()
        {
            if (!has_current_) {
                return info::empty_string(analyser_.mr_);
            }

            if (!flushed_) {
                return std::move(current_);
            }

            return info::from_formula(
                analyser_.mr_, analyser_.arena_.combine(kind::conjunction, conjunction_,
                                   analyser_.take_match(current_)));
        }

    protected:
        analyser &analyser_; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
        bool has_current_{false};
        bool flushed_{false};
        info current_;
        // What is known about the subexpressions before current_
        handle conjunction_{formula_arena::all};
    };

    // NOLINTNEXTLINE(misc-no-recursion)
    info visit(Regexp *re, unsigned depth)
    {
        if (failed_ || depth > max_analysis_depth || ++steps_ > max_steps_) {
            failed_ = true;
            return info::anything(mr_);
        }

        switch (re->op()) {
        case re2::kRegexpNoMatch:
            return info::nothing(mr_);
        case re2::kRegexpEmptyMatch:
        case re2::kRegexpBeginLine:
        case re2::kRegexpEndLine:
        case re2::kRegexpBeginText:
        case re2::kRegexpEndText:
        case re2::kRegexpWordBoundary:
        case re2::kRegexpNoWordBoundary:
            return info::empty_string(mr_);
        case re2::kRegexpLiteral: {
            auto c = atom_character(re->rune());
            if (c < 0) {
                return info::anything(mr_);
            }
            return exact_string(single_character(c));
        }
        case re2::kRegexpLiteralString: {
            concatenation concat{*this};
            // Runs of ASCII characters are copied to the arena at once
            auto *buffer = static_cast<char *>(mr_->allocate(re->nrunes(), 1));
            std::size_t run = 0;
            for (int i = 0; i < re->nrunes(); ++i) {
                auto c = atom_character(re->runes()[i]);
                if (c >= 0) {
                    buffer[run++] = static_cast<char>(c);
                    continue;
                }
                if (run > 0) {
                    concat.add(exact_string({buffer, run}));
                    buffer += run;
                    run = 0;
                }
                concat.add(info::anything(mr_));
            }
            if (run > 0) {
                concat.add(exact_string({buffer, run}));
            }
            return concat.finish();
        }
        case re2::kRegexpConcat: {
            concatenation concat{*this};
            for (int i = 0; i < re->nsub(); ++i) { concat.add(visit(re->sub()[i], depth + 1)); }
            return concat.finish();
        }
        case re2::kRegexpAlternate: {
            auto result = info::nothing(mr_);
            for (int i = 0; i < re->nsub() && !result.is_anything(); ++i) {
                // Once an alternative matches anything, so does the alternation
                result = alternate(std::move(result), visit(re->sub()[i], depth + 1));
            }
            return result;
        }
        case re2::kRegexpQuest:
            // Either the subexpression or nothing
            return alternate(visit(re->sub()[0], depth + 1), info::empty_string(mr_));
        case re2::kRegexpStar:
            return repetition(visit(re->sub()[0], depth + 1), 0);
        case re2::kRegexpPlus:
            return repetition(visit(re->sub()[0], depth + 1), 1);
        case re2::kRegexpRepeat:
            if (re->min() == 0 && re->max() == 1) {
                return alternate(visit(re->sub()[0], depth + 1), info::empty_string(mr_));
            }
            return repetition(visit(re->sub()[0], depth + 1), re->min());
        case re2::kRegexpCapture:
            return visit(re->sub()[0], depth + 1);
        case re2::kRegexpCharClass: {
            auto *cc = re->cc();
            if (cc == nullptr || cc->size() > max_class_characters) {
                return info::anything(mr_);
            }
            string_set characters{mr_};
            for (const auto &range : *cc) {
                for (Rune r = range.lo; r <= range.hi; ++r) {
                    auto c = atom_character(r);
                    if (c < 0) {
                        return info::anything(mr_);
                    }
                    characters.emplace_back(single_character(c));
                }
            }
            return info::exact_set(std::move(characters));
        }
        case re2::kRegexpAnyChar:
        case re2::kRegexpAnyByte:
        case re2::kRegexpHaveMatch:
        default:
            return info::anything(mr_);
        }
    }

    // The formula satisfied by every string matched: one of the exact strings
    // is present, or the formula holds
    handle take_match(info &i)
    {
        return arena_.combine(kind::disjunction, arena_.disjunction_of(i.strings), i.match);
    }

    // Moves the exact strings to the formula if there are too many of them,
    // and drops them if the formula is always true
    void normalise_size(info &i)
    {
        if (i.strings.size() > max_exact_strings) {
            i.match = take_match(i);
            i.strings.clear();
        }
        if (i.is_anything()) {
            i.strings.clear();
        }
    }

    info alternate(info a, info b)
    {
        info result{mr_};
        result.match = arena_.combine(kind::disjunction, a.match, b.match);
        if (!result.is_anything()) {
            result.strings = std::move(a.strings);
            result.strings.reserve(result.strings.size() + b.strings.size());
            std::move(b.strings.begin(), b.strings.end(), std::back_inserter(result.strings));
            normalise(result.strings);
        }
        normalise_size(result);
        return result;
    }

    // At least `min` repetitions of a subexpression: when min is zero, either
    // nothing or something containing a match of the subexpression.
    info repetition(info sub, int min)
    {
        auto result = info::from_formula(mr_, take_match(sub));
        if (min == 0) {
            result.strings.emplace_back();
        }
        normalise_size(result);
        return result;
    }

    info exact_string(std::string_view str)
    {
        string_set strings{mr_};
        strings.emplace_back(str);
        return {std::move(strings), formula_arena::none};
    }

    std::pmr::memory_resource *mr_;
    formula_arena arena_;
    unsigned max_steps_;
    unsigned steps_{0};
    bool failed_{false};
};

bool anchored_at_start(Regexp *re)
{
    while (re->op() == re2::kRegexpConcat || re->op() == re2::kRegexpCapture) {
        if (re->nsub() == 0) {
            return false;
        }
        re = re->sub()[0];
    }
    return re->op() == re2::kRegexpBeginText || re->op() == re2::kRegexpBeginLine;
}

} // namespace

class regex_prefilter_builder {
public:
    static std::unique_ptr<regex_prefilter> build(const formula_arena &arena, handle root)
    {
        std::unique_ptr<regex_prefilter> pf{new regex_prefilter};
        regex_prefilter_builder builder{pf.get(), arena};

        // Atoms are deduplicated and numbered in the order of their hashes
        builder.collect_atoms(root);
        std::sort(builder.atoms_.begin(), builder.atoms_.end(),
            [](const auto &l, const auto &r) { return l.key < r.key; });
        builder.index_.resize(arena.atom_count());
        for (std::size_t i = 0; i < builder.atoms_.size(); ++i) {
            const auto &[key, string_index] = builder.atoms_[i];
            if (i == 0 || key != builder.atoms_[i - 1].key) {
                if (pf->atoms_.size() >= max_formula_atoms) {
                    return nullptr;
                }
                pf->atoms_.emplace_back(key.second);
                pf->hashes_.emplace_back(key.first);
                pf->mask_ |= regex_prefilter::mask_bit(key.first);
            }
            builder.index_[string_index] = static_cast<uint32_t>(pf->atoms_.size() - 1);
        }

        builder.emit(root, 1);

        const auto &node = arena[root];
        pf->disjunction_only_ = node.type == kind::atom;
        if (node.type == kind::disjunction) {
            pf->disjunction_only_ = true;
            for (auto sub = node.first; sub != formula_arena::all; sub = arena[sub].next) {
                pf->disjunction_only_ = pf->disjunction_only_ && arena[sub].type == kind::atom;
            }
        }

        return pf;
    }

protected:
    regex_prefilter_builder(regex_prefilter *pf, const formula_arena &arena)
        : pf_(pf), arena_(&arena)
    {}

    // NOLINTNEXTLINE(misc-no-recursion)
    void collect_atoms(handle f)
    {
        const auto &node = (*arena_)[f];
        if (node.type == kind::atom) {
            auto atom = arena_->atom_of(f);
            atoms_.push_back({{regex_prefilter::hash_atom(atom), atom}, node.first});
            return;
        }
        for (auto sub = node.first; sub != formula_arena::all; sub = (*arena_)[sub].next) {
            collect_atoms(sub);
        }
    }

    // Emits the formula in postfix order, using binary operations so that the
    // evaluation stack never exceeds the depth of the formula.
    // NOLINTNEXTLINE(misc-no-recursion)
    void emit(handle f, std::size_t stack_size)
    {
        pf_->max_stack_ = std::max(pf_->max_stack_, stack_size);
        const auto &node = (*arena_)[f];
        if (node.type == kind::atom) {
            pf_->program_.push_back({regex_prefilter::opcode::atom, index_[node.first]});
            return;
        }

        const auto code = node.type == kind::conjunction ? regex_prefilter::opcode::conjunction
                                                         : regex_prefilter::opcode::disjunction;
        bool first = true;
        for (auto sub = node.first; sub != formula_arena::all; sub = (*arena_)[sub].next) {
            emit(sub, first ? stack_size : stack_size + 1);
            if (!first) {
                pf_->program_.push_back({code, 0});
            }
            first = false;
        }
    }

    regex_prefilter *pf_;
    const formula_arena *arena_;
    struct collected_atom {
        std::pair<uint64_t, std::string_view> key; // hash and value
        uint32_t string_index;                     // in the arena
    };
    std::vector<collected_atom> atoms_;
    // Index in the prefilter of each atom of the arena, by string index
    std::vector<uint32_t> index_;
};

std::unique_ptr<regex_prefilter> regex_prefilter::from_regex(const re2::RE2 &regex)
{
    auto *re = regex.Regexp();
    if (re == nullptr) {
        return nullptr;
    }

    // The analysis creates many short-lived strings and vectors: they are
    // allocated from an arena, which must outlive them.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    std::array<std::byte, 8192> buffer;
    std::pmr::monotonic_buffer_resource arena{buffer.data(), buffer.size()};

    analyser analysis{
        &arena, anchored_at_start(re) ? max_anchored_analysis_steps : max_analysis_steps};
    auto match = analysis.analyse(re);
    // A formula which is always true can't filter anything; one which is
    // never true is only expected for expressions which can't match anything,
    // but it is safer to not rely on that.
    if (!match.has_value() || *match == formula_arena::all || *match == formula_arena::none) {
        return nullptr;
    }

    return regex_prefilter_builder::build(analysis.arena(), *match);
}

bool regex_prefilter::may_match(std::span<const uint64_t> present_atoms) const
{
    if (present_atoms.empty()) {
        return false;
    }

    const auto contains = [](std::span<const uint64_t> set, uint64_t value) {
        return std::binary_search(set.begin(), set.end(), value);
    };

    if (disjunction_only_) {
        if (present_atoms.size() <= hashes_.size()) {
            return std::any_of(present_atoms.begin(), present_atoms.end(),
                [&](uint64_t hash) { return contains(hashes_, hash); });
        }
        return std::any_of(hashes_.begin(), hashes_.end(),
            [&](uint64_t hash) { return contains(present_atoms, hash); });
    }

    // The stack never exceeds max_formula_depth + 1 elements, see emit
    std::array<bool, max_formula_depth + 2> stack{};
    std::size_t top = 0;
    for (const auto &ins : program_) {
        switch (ins.code) {
        case opcode::atom:
            stack[top++] = contains(present_atoms, hashes_[ins.arg]);
            break;
        case opcode::conjunction:
            --top;
            stack[top - 1] = stack[top - 1] && stack[top];
            break;
        case opcode::disjunction:
            --top;
            stack[top - 1] = stack[top - 1] || stack[top];
            break;
        }
    }
    return stack[0];
}

std::string regex_prefilter::to_string() const
{
    // Rebuilds the n-ary formula from the binary postfix program
    struct element {
        std::string str;
        opcode code;
        std::size_t count;
    };
    std::vector<element> stack;
    for (const auto &ins : program_) {
        if (ins.code == opcode::atom) {
            stack.push_back({'"' + atoms_[ins.arg] + '"', opcode::atom, 1});
            continue;
        }

        auto rhs = std::move(stack.back());
        stack.pop_back();
        auto &lhs = stack.back();
        const char *sep = ins.code == opcode::conjunction ? " & " : " | ";
        auto unwrap = [&](element &e) {
            if (e.code == ins.code) {
                // Remove the enclosing parentheses
                return e.str.substr(1, e.str.size() - 2);
            }
            return e.str;
        };
        lhs.str = '(' + unwrap(lhs) + sep + unwrap(rhs) + ')';
        lhs.code = ins.code;
    }
    return stack.empty() ? std::string{} : stack.back().str;
}

uint64_t regex_prefilter::hash_atom(std::string_view atom)
{
    // FNV-1a followed by a finaliser, so that every bit is usable for masks
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (auto c : atom) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 0x100000001b3ULL;
    }
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;
    return hash;
}

} // namespace ddwaf::matcher
