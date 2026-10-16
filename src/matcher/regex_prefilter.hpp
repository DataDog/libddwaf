// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace re2 {
class RE2;
} // namespace re2

namespace ddwaf::matcher {

// A regex_prefilter is a necessary condition for a regular expression to
// match: a monotone boolean formula over literal strings ("atoms") which any
// matching input must contain. For example, any match of
// `union.*?select.*?from` contains "union", "select" and "from", and any match
// of `<(?:script|iframe)` contains "<script" or "<iframe".
//
// The prefilter is evaluated on the set of atoms present in the input, which a
// literal_scanner finds for all the regular expressions of a ruleset in a
// single pass, so that most regular expressions can be ruled out without
// running RE2 at all.
//
// The model is deliberately simple, so that the prefilter can be exact, i.e.
// never reject an input that the regular expression matches:
//   - Atoms are lowercase ASCII and are searched for ASCII case-insensitively.
//     Atoms are at least min_atom_length characters long.
//   - Non-ASCII characters are never part of an atom; a non-ASCII character or
//     class of the expression behaves as a wildcard.
//   - The only non-ASCII characters which can match an ASCII character in a
//     case-insensitive expression are U+017F (LATIN SMALL LETTER LONG S) and
//     U+212A (KELVIN SIGN). Inputs containing them are not filtered at all
//     (see literal_scanner::scan).
class regex_prefilter {
public:
    static constexpr std::size_t min_atom_length = 3;

    // Returns nullptr if the regular expression has no usable literal
    // requirement (for example `\d+` or `(?:a|b)c`).
    static std::unique_ptr<regex_prefilter> from_regex(const re2::RE2 &regex);

    regex_prefilter(const regex_prefilter &) = delete;
    regex_prefilter(regex_prefilter &&) = delete;
    regex_prefilter &operator=(const regex_prefilter &) = delete;
    regex_prefilter &operator=(regex_prefilter &&) = delete;
    ~regex_prefilter() = default;

    // Evaluates the prefilter on the hashes (see hash_atom) of all the atoms
    // present in the input, sorted in ascending order. The hashes of atoms
    // which are not part of this prefilter are ignored, so the same set can be
    // used for every prefilter of a ruleset.
    [[nodiscard]] bool may_match(std::span<const uint64_t> present_atoms) const;

    // Bloom mask of the atoms of this prefilter: if the mask of the atoms
    // present in an input doesn't intersect it, the prefilter can't pass.
    [[nodiscard]] uint64_t atom_mask() const { return mask_; }
    // Atoms, in ascending order of their hashes
    [[nodiscard]] const std::vector<std::string> &atoms() const { return atoms_; }
    // atom_hashes()[i] is the hash of atoms()[i]
    [[nodiscard]] const std::vector<uint64_t> &atom_hashes() const { return hashes_; }

    // Human-readable formula, for testing
    [[nodiscard]] std::string to_string() const;

    static uint64_t hash_atom(std::string_view atom);
    static constexpr uint64_t mask_bit(uint64_t hash) { return uint64_t{1} << (hash >> 58); }

    // Memoisation of literal_scanner::covers, keyed by scanner identifier, as
    // a regex_prefilter can be shared by several rulesets
    [[nodiscard]] uint64_t coverage_hint() const
    {
        return coverage_hint_.load(std::memory_order_relaxed);
    }
    void set_coverage_hint(uint64_t value) const
    {
        coverage_hint_.store(value, std::memory_order_relaxed);
    }

protected:
    // Postfix program: an atom pushes its presence, a conjunction (or a
    // disjunction) of `arg` elements pops them and pushes the result.
    enum class opcode : uint8_t { atom, conjunction, disjunction };
    struct instruction {
        opcode code;
        uint32_t arg;
    };

    regex_prefilter() = default;

    std::vector<std::string> atoms_;
    std::vector<uint64_t> hashes_; // sorted, hashes_[i] is the hash of atoms_[i]
    std::vector<instruction> program_;
    std::size_t max_stack_{0};
    uint64_t mask_{0};
    // The formula is a single atom or a disjunction of atoms, so it passes
    // iff any of its atoms is present
    bool disjunction_only_{false};

    mutable std::atomic<uint64_t> coverage_hint_{0};

    friend class regex_prefilter_builder;
};

} // namespace ddwaf::matcher
