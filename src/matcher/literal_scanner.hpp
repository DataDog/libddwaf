// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "matcher/regex_prefilter.hpp"

namespace ddwaf::matcher {

// Finds, in a single pass over an input, which of the atoms of a set of
// regex_prefilter are present in it, ASCII case-insensitively.
//
// Candidate positions are found through bitmaps of the hashes of the first
// four characters of every atom, or three for atoms of three characters (the
// minimum), and verified against the atoms sharing that hash. Four characters
// are much less likely than three to match by chance in ordinary text.
class literal_scanner {
public:
    // Scratch space for scan, owned by the caller (one per thread).
    struct scratch {
        std::vector<uint32_t> seen;
        uint32_t stamp{0};
    };

    struct result {
        // The input contains characters which can match an ASCII character
        // in a case-insensitive regular expression (U+017F, U+212A), the
        // prefilters can't be relied upon.
        bool unfiltered{false};
        // Bloom mask of the atoms found, see regex_prefilter::mask_bit
        uint64_t mask{0};
    };

    static std::shared_ptr<const literal_scanner> build(
        std::span<const regex_prefilter *const> prefilters);

    literal_scanner(const literal_scanner &) = delete;
    literal_scanner(literal_scanner &&) = delete;
    literal_scanner &operator=(const literal_scanner &) = delete;
    literal_scanner &operator=(literal_scanner &&) = delete;
    ~literal_scanner() = default;

    // Appends to found the sorted hashes of the atoms present in str.
    result scan(std::string_view str, scratch &scr, std::vector<uint64_t> &found) const;

    // Whether every atom of the prefilter is searched for by this scanner,
    // which is required for its scan results to be valid for the prefilter.
    [[nodiscard]] bool covers(const regex_prefilter &prefilter) const;

    // Unique for the lifetime of the process
    [[nodiscard]] uint64_t id() const { return id_; }
    [[nodiscard]] std::size_t size() const { return entries_.size(); }

protected:
    static constexpr unsigned filter_bits = 16;
    static constexpr unsigned bucket_bits = 12;

    struct entry {
        uint64_t hash;
        uint32_t offset;
        uint32_t length;
        // Hash of the first four characters, or three if the atom is that short
        uint16_t prefix;
    };

    using filter = std::array<uint64_t, (std::size_t{1} << filter_bits) / 64>;

    literal_scanner() = default;

    static uint16_t prefix_hash(uint32_t prefix)
    {
        return static_cast<uint16_t>((prefix * 0x9E3779B1U) >> (32 - filter_bits));
    }

    static bool test(const filter &f, uint16_t hash)
    {
        return ((f[hash >> 6] >> (hash & 63)) & 1) != 0;
    }

    void verify(const unsigned char *str, std::size_t remaining, uint16_t prefix, bool short_atoms,
        scratch &scr, std::vector<uint64_t> &found, uint64_t &mask) const;

    uint64_t id_{0};
    std::string literals_;
    // Sorted by prefix hash
    std::vector<entry> entries_;
    // Index of the first entry of each bucket (prefix hash >> (filter_bits - bucket_bits))
    std::vector<uint32_t> buckets_;
    // Prefix hashes of the atoms of three characters, and of the longer ones
    filter short_filter_{};
    filter long_filter_{};
    // Hashes and views of literals_, sorted
    std::vector<std::pair<uint64_t, std::string_view>> atoms_;
};

} // namespace ddwaf::matcher
