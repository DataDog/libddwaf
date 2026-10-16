// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "matcher/literal_scanner.hpp"
#include "matcher/regex_prefilter.hpp"

namespace ddwaf::matcher {

namespace {

constexpr std::array<unsigned char, 256> make_lowercase_table()
{
    std::array<unsigned char, 256> table{};
    for (unsigned i = 0; i < table.size(); ++i) {
        table[i] = static_cast<unsigned char>((i >= 'A' && i <= 'Z') ? i + ('a' - 'A') : i);
    }
    return table;
}

constexpr auto lowercase_table = make_lowercase_table();

// Lowercases the ASCII letters of the eight bytes of a word
constexpr uint64_t lowercase_word(uint64_t word)
{
    const uint64_t low_bits = word & 0x7F7F7F7F7F7F7F7FULL;
    // The high bit of each byte is set if the byte is at least 'A' (0x41)
    const uint64_t at_least_a = low_bits + 0x3F3F3F3F3F3F3F3FULL;
    // ... or greater than 'Z' (0x5A)
    const uint64_t above_z = low_bits + 0x2525252525252525ULL;
    const uint64_t ascii = ~word & 0x8080808080808080ULL;
    const uint64_t upper = ascii & at_least_a & ~above_z;
    return word | (upper >> 2);
}

// Packs the first characters of a string in little-endian order, matching
// the bytes of a word loaded from memory
constexpr uint32_t prefix_of(const unsigned char *str, std::size_t length)
{
    uint32_t prefix = 0;
    for (std::size_t i = 0; i < length; ++i) { prefix |= static_cast<uint32_t>(str[i]) << (8 * i); }
    return prefix;
}

// Identifiers are even, so that regex_prefilter::coverage_hint can use the
// lowest bit to memoise negative results.
std::atomic<uint64_t> next_scanner_id{2};

} // namespace

std::shared_ptr<const literal_scanner> literal_scanner::build(
    std::span<const regex_prefilter *const> prefilters)
{
    std::shared_ptr<literal_scanner> scanner{new literal_scanner};
    scanner->id_ = next_scanner_id.fetch_add(2, std::memory_order_relaxed);

    // Atoms are deduplicated by hash first, and then by value
    std::vector<std::pair<uint64_t, std::string_view>> unique_atoms;
    for (const auto *prefilter : prefilters) {
        const auto &atoms = prefilter->atoms();
        const auto &hashes = prefilter->atom_hashes();
        for (std::size_t i = 0; i < atoms.size(); ++i) {
            if (atoms[i].size() >= regex_prefilter::min_atom_length) {
                unique_atoms.emplace_back(hashes[i], atoms[i]);
            }
        }
    }
    std::sort(unique_atoms.begin(), unique_atoms.end());
    unique_atoms.erase(std::unique(unique_atoms.begin(), unique_atoms.end()), unique_atoms.end());

    std::size_t total_length = 0;
    for (auto [hash, atom] : unique_atoms) { total_length += atom.size(); }

    // literals_ doesn't grow past this, so the views into it remain valid
    scanner->literals_.reserve(total_length);
    scanner->atoms_.reserve(unique_atoms.size());
    scanner->entries_.reserve(unique_atoms.size());
    for (auto [hash, atom] : unique_atoms) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *chars = reinterpret_cast<const unsigned char *>(atom.data());
        scanner->entries_.push_back({.hash = hash,
            .offset = static_cast<uint32_t>(scanner->literals_.size()),
            .length = static_cast<uint32_t>(atom.size()),
            .prefix = prefix_hash(prefix_of(chars, std::min<std::size_t>(atom.size(), 4)))});
        scanner->atoms_.emplace_back(hash,
            std::string_view{scanner->literals_.data() + scanner->literals_.size(), atom.size()});
        scanner->literals_.append(atom);
    }

    std::sort(scanner->entries_.begin(), scanner->entries_.end(),
        [](const entry &l, const entry &r) { return l.prefix < r.prefix; });

    constexpr unsigned bucket_shift = filter_bits - bucket_bits;
    scanner->buckets_.assign((std::size_t{1} << bucket_bits) + 1, 0);
    for (const auto &e : scanner->entries_) {
        ++scanner->buckets_[(e.prefix >> bucket_shift) + 1];
        auto &f = e.length == regex_prefilter::min_atom_length ? scanner->short_filter_
                                                               : scanner->long_filter_;
        f[e.prefix >> 6] |= uint64_t{1} << (e.prefix & 63);
    }
    for (std::size_t i = 1; i < scanner->buckets_.size(); ++i) {
        scanner->buckets_[i] += scanner->buckets_[i - 1];
    }

    // The scanner covers the prefilters it's built from by definition
    for (const auto *prefilter : prefilters) { prefilter->set_coverage_hint(scanner->id_); }

    return scanner;
}

literal_scanner::result literal_scanner::scan(
    std::string_view str, scratch &scr, std::vector<uint64_t> &found) const
{
    result res;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *s = reinterpret_cast<const unsigned char *>(str.data());
    const std::size_t size = str.size();
    const std::size_t first_found = found.size();

    if (scr.seen.size() != entries_.size()) {
        scr.seen.assign(entries_.size(), 0);
        scr.stamp = 0;
    }
    if (++scr.stamp == 0) {
        std::fill(scr.seen.begin(), scr.seen.end(), 0);
        scr.stamp = 1;
    }

    // Every position i is checked for an atom starting with s[i..i+3], or
    // s[i..i+2] for the atoms of three characters. Words of eight bytes are
    // lowercased at once and provide the prefixes of five positions.
    static_assert(regex_prefilter::min_atom_length == 3);
    uint64_t high_bits = 0;
    std::size_t i = 0;
    if (size >= regex_prefilter::min_atom_length && !entries_.empty()) {
        if constexpr (std::endian::native == std::endian::little) {
            for (; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t) - 3) {
                uint64_t word;
                std::memcpy(&word, s + i, sizeof(word));
                high_bits |= word;
                word = lowercase_word(word);
                for (unsigned k = 0; k < sizeof(uint64_t) - 3; ++k) {
                    const auto prefix = static_cast<uint32_t>(word >> (8 * k));
                    const auto long_hash = prefix_hash(prefix);
                    if (test(long_filter_, long_hash)) {
                        verify(s + i + k, size - i - k, long_hash, false, scr, found, res.mask);
                    }
                    const auto short_hash = prefix_hash(prefix & 0xFFFFFF);
                    if (test(short_filter_, short_hash)) {
                        verify(s + i + k, size - i - k, short_hash, true, scr, found, res.mask);
                    }
                }
            }
        }

        for (; i + 2 < size; ++i) {
            high_bits |= s[i];
            std::array<unsigned char, 4> chars{lowercase_table[s[i]], lowercase_table[s[i + 1]],
                lowercase_table[s[i + 2]], i + 3 < size ? lowercase_table[s[i + 3]] : uint8_t{0}};
            const auto short_hash = prefix_hash(prefix_of(chars.data(), 3));
            if (test(short_filter_, short_hash)) {
                verify(s + i, size - i, short_hash, true, scr, found, res.mask);
            }
            if (i + 3 < size) {
                const auto long_hash = prefix_hash(prefix_of(chars.data(), 4));
                if (test(long_filter_, long_hash)) {
                    verify(s + i, size - i, long_hash, false, scr, found, res.mask);
                }
            }
        }
    }
    for (; i < size; ++i) { high_bits |= s[i]; }

    if ((high_bits & 0x8080808080808080ULL) != 0) {
        // U+017F and U+212A fold to 's' and 'k' respectively
        res.unfiltered = str.find("\xC5\xBF") != std::string_view::npos ||
                         str.find("\xE2\x84\xAA") != std::string_view::npos;
    }

    if (found.size() - first_found > 1) {
        std::sort(found.begin() + static_cast<std::ptrdiff_t>(first_found), found.end());
        // Distinct atoms only have the same hash on (unlikely) collisions
        found.erase(
            std::unique(found.begin() + static_cast<std::ptrdiff_t>(first_found), found.end()),
            found.end());
    }

    return res;
}

void literal_scanner::verify(const unsigned char *str, std::size_t remaining, uint16_t prefix,
    bool short_atoms, scratch &scr, std::vector<uint64_t> &found, uint64_t &mask) const
{
    constexpr unsigned bucket_shift = filter_bits - bucket_bits;
    const auto bucket = prefix >> bucket_shift;
    for (auto j = buckets_[bucket]; j < buckets_[bucket + 1]; ++j) {
        const auto &e = entries_[j];
        if (e.prefix != prefix || (e.length == regex_prefilter::min_atom_length) != short_atoms ||
            e.length > remaining || scr.seen[j] == scr.stamp) {
            continue;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *literal = reinterpret_cast<const unsigned char *>(literals_.data() + e.offset);
        std::size_t k = 0;
        for (; k < e.length && lowercase_table[str[k]] == literal[k]; ++k) {}
        if (k == e.length) {
            scr.seen[j] = scr.stamp;
            found.push_back(e.hash);
            mask |= regex_prefilter::mask_bit(e.hash);
        }
    }
}

bool literal_scanner::covers(const regex_prefilter &prefilter) const
{
    const auto &atoms = prefilter.atoms();
    const auto &hashes = prefilter.atom_hashes();
    for (std::size_t i = 0; i < atoms.size(); ++i) {
        if (!std::binary_search(
                atoms_.begin(), atoms_.end(), std::pair{hashes[i], std::string_view{atoms[i]}})) {
            return false;
        }
    }
    return true;
}

} // namespace ddwaf::matcher
