// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace ddwaf {

// A quick test of whether a string may occur within a fixed text, used by the
// injection detectors to discard most request parameters without searching
// for them within the resource (an SQL statement, a URL, a shell command).
//
// The (hashed) pairs of consecutive bytes of the text are recorded in a
// bitmap; a needle with a pair absent from the bitmap can't be a substring of
// the text. There are no false negatives, since every pair of bytes of a
// substring is also a pair of bytes of the text, while false positives only
// cost the search which would have been performed anyway.
//
// Building the bitmap costs a pass over the text, so it's deferred until a
// number of needles have been tested: when only a few parameters are
// searched, as with most requests, the searches are cheaper than the bitmap.
class substring_filter {
public:
    // The number of needles which are let through before building the bitmap
    static constexpr unsigned unfiltered_needles = 16;

    explicit substring_filter(std::string_view text) : text_(text) {}

    // Returns false if the needle can't occur within the text, true if it may
    [[nodiscard]] bool may_contain(std::string_view needle)
    {
        if (needle.size() > text_.size()) {
            return false;
        }

        if (needle.size() < 2) {
            return true;
        }

        if (!built_) {
            if (unfiltered_ > 0) {
                --unfiltered_;
                return true;
            }
            build();
        }

        return may_contain_pairs(needle);
    }

private:
    static constexpr std::size_t bitmap_bits = 4096;
    static constexpr std::size_t word_bits = 64;

    static std::size_t pair_hash(unsigned char first, unsigned char second) noexcept
    {
        // Fibonacci hashing of the 16-bit pair, taking the top 12 bits
        static constexpr uint32_t multiplier = 0x9E3779B1U;
        static constexpr unsigned shift = 32 - 12;
        static_assert((std::size_t{1} << (32 - shift)) == bitmap_bits);

        const uint32_t pair = (static_cast<uint32_t>(first) << 8) | second;
        return static_cast<uint32_t>(pair * multiplier) >> shift;
    }

    void build() noexcept
    {
        built_ = true;
        bitmap_.fill(0);

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *data = reinterpret_cast<const unsigned char *>(text_.data());
        for (std::size_t i = 1; i < text_.size(); ++i) {
            const auto h = pair_hash(data[i - 1], data[i]);
            bitmap_[h / word_bits] |= uint64_t{1} << (h % word_bits);
        }
    }

    [[nodiscard]] bool has_pair(const unsigned char *pair) const noexcept
    {
        const auto h = pair_hash(pair[0], pair[1]);
        return (bitmap_[h / word_bits] & (uint64_t{1} << (h % word_bits))) != 0;
    }

    [[nodiscard]] bool may_contain_pairs(std::string_view needle) const noexcept
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *data = reinterpret_cast<const unsigned char *>(needle.data());
        const std::size_t last = needle.size() - 2;

        // The first and last pairs, then the pairs at the middle and at the
        // quarters of the needle, so that a long needle costs as much as a
        // short one (in a short needle, some of these are the same pair)
        return has_pair(data) && has_pair(data + last) && has_pair(data + (last / 2)) &&
               has_pair(data + (last / 4)) && has_pair(data + (last - (last / 4)));
    }

    std::string_view text_;
    unsigned unfiltered_{unfiltered_needles};
    bool built_{false};
    // Only initialised once built
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    std::array<uint64_t, bitmap_bits / word_bits> bitmap_;
};

} // namespace ddwaf
