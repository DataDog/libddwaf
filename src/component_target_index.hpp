// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "context_allocator.hpp"
#include "target_address.hpp"

namespace ddwaf {

// Index of the components of a collection (the processors or filters of a
// ruleset, by position) by the targets they reference, which determines the
// components to evaluate again when a target is updated.
class component_target_index {
public:
    // Number of components represented by each word of a component_bitset
    static constexpr std::size_t word_bits = 64;

    // Components of the collection, those of a word of a component_bitset
    struct component_set {
        uint32_t word;
        uint64_t mask;

        bool operator==(const component_set &) const = default;
    };

    // A target referenced by a component, given by its position
    struct reference {
        target_index target;
        std::size_t component;
    };

    component_target_index() = default;

    // References may be in any order and contain duplicates
    explicit component_target_index(std::vector<reference> references);

    // Returns the components referencing the target, the result is empty if,
    // and only if, the target isn't referenced by any component.
    [[nodiscard]] std::span<const component_set> find(target_index target) const
    {
        if (target >= ranges_.size()) {
            return {};
        }

        const auto &range = ranges_[target];
        return {sets_.data() + range.begin, sets_.data() + range.end};
    }

protected:
    // The component sets of a target, indexed by target (which are dense, see
    // target_index), a target without components has an empty range.
    struct range {
        uint32_t begin{0};
        uint32_t end{0};
    };

    std::vector<range> ranges_;
    std::vector<component_set> sets_;
};

// Bitset with one bit per component of a collection, in collection order. The
// first word is stored inline, so that collections of up to 64 components,
// the usual case, require no allocation; the others, if any, are allocated
// with the context allocator.
class component_bitset {
public:
    static constexpr std::size_t word_bits = component_target_index::word_bits;

    component_bitset() = default;

    // Bitset of the given number of components, all of them set
    explicit component_bitset(std::size_t count)
    {
        if (count == 0) {
            return;
        }

        const auto words = (count + word_bits - 1) / word_bits;
        first_ = ~uint64_t{0};
        if (words > 1) {
            others_.assign(words - 1, ~uint64_t{0});
        }

        if (const auto remainder = count % word_bits; remainder != 0) {
            word(words - 1) = (uint64_t{1} << remainder) - 1;
        }
    }

    [[nodiscard]] bool test(std::size_t pos) const
    {
        return (word(pos / word_bits) & bit(pos)) != 0;
    }

    void reset(std::size_t pos) { word(pos / word_bits) &= ~bit(pos); }

    // The components must be within the bitset
    void set(std::span<const component_target_index::component_set> components)
    {
        for (const auto &[index, mask] : components) { word(index) |= mask; }
    }

protected:
    static constexpr uint64_t bit(std::size_t pos) { return uint64_t{1} << (pos % word_bits); }

    [[nodiscard]] uint64_t word(std::size_t index) const
    {
        return index == 0 ? first_ : others_[index - 1];
    }

    uint64_t &word(std::size_t index) { return index == 0 ? first_ : others_[index - 1]; }

    uint64_t first_{0};
    memory::vector<uint64_t> others_;
};

} // namespace ddwaf
