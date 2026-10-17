// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "dynamic_string.hpp"
#include "expiring_string_list.hpp"
#include "indexed_multivector.hpp"
#include "matcher/exact_match.hpp"

namespace ddwaf::matcher {

namespace {

uint64_t hash_string(std::string_view str) noexcept;

} // namespace

exact_match::exact_match(std::vector<std::string> &&data) { build(data); }

exact_match::exact_match(const std::vector<std::pair<std::string, uint64_t>> &data)
{
    build(data);
}

exact_match::exact_match(
    const indexed_multivector<std::string, std::pair<std::string, uint64_t>> &data)
{
    build(data);
}

exact_match::exact_match(const indexed_multivector<std::string, expiring_string_list::value_type,
    expiring_string_list> &data)
{
    build(data);
}

std::pair<bool, dynamic_string> exact_match::match_impl(std::string_view str) const
{
    if (entries_.empty() || str.empty() || str.data() == nullptr) {
        return {false, {}};
    }

    const auto *expiration = find(str);
    if (expiration == nullptr) {
        return {false, {}};
    }

    if (*expiration > 0) {
        const uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
                                 .count();
        if (*expiration < now) {
            return {false, {}};
        }
    }
    return {true, std::string{str}};
}

// Builds the table from a list of strings (which never expire) or of
// (string, expiration) pairs. When a value appears more than once, the latest
// expiration prevails, with 0 meaning that the value never expires.
template <typename T> void exact_match::build(const T &data)
{
    std::size_t bytes = 0;
    std::size_t count = 0;
    for (const auto &item : data) {
        if constexpr (std::is_convertible_v<decltype(item), std::string_view>) {
            bytes += std::string_view{item}.size();
        } else {
            bytes += std::string_view{item.first}.size();
        }
        ++count;
    }

    if (count == 0) {
        return;
    }

    buffer_.reserve(bytes);
    entries_.reserve(count);
    // Keep the load factor at or below 50%
    slots_.assign(std::bit_ceil(count * 2), 0);
    const std::size_t mask = slots_.size() - 1;

    for (const auto &item : data) {
        std::string_view str;
        uint64_t expiration = 0;
        if constexpr (std::is_convertible_v<decltype(item), std::string_view>) {
            str = item;
        } else {
            str = item.first;
            expiration = item.second;
        }

        const uint64_t hash = hash_string(str);
        const uint64_t tag = hash & 0xFFFFFFFF00000000ULL;
        for (std::size_t i = hash & mask;; i = (i + 1) & mask) {
            auto &slot = slots_[i];
            if (slot == 0) {
                entries_.push_back({buffer_.size(), str.size(), expiration});
                buffer_.append(str);
                slot = tag | entries_.size();
                max_length_ = std::max(max_length_, str.size());
                break;
            }

            if ((slot & 0xFFFFFFFF00000000ULL) != tag) {
                continue;
            }

            auto &e = entries_[(slot & 0xFFFFFFFFULL) - 1];
            if (std::string_view{buffer_}.substr(e.offset, e.length) == str) {
                if (e.expiration != 0 && (expiration == 0 || expiration > e.expiration)) {
                    e.expiration = expiration;
                }
                break;
            }
        }
    }
}

const uint64_t *exact_match::find(std::string_view str) const
{
    if (str.size() > max_length_) {
        return nullptr;
    }

    const uint64_t hash = hash_string(str);
    const uint64_t tag = hash & 0xFFFFFFFF00000000ULL;
    const std::size_t mask = slots_.size() - 1;
    for (std::size_t i = hash & mask;; i = (i + 1) & mask) {
        const auto slot = slots_[i];
        if (slot == 0) {
            return nullptr;
        }

        if ((slot & 0xFFFFFFFF00000000ULL) == tag) {
            const auto &e = entries_[(slot & 0xFFFFFFFFULL) - 1];
            if (e.length == str.size() &&
                std::memcmp(buffer_.data() + e.offset, str.data(), str.size()) == 0) {
                return &e.expiration;
            }
        }
    }
}

namespace {

// A simple multiply-xorshift hash over 8-byte words. It doesn't need to resist
// adversarial inputs: the table contents come from the configuration, and
// lookups don't modify it.
uint64_t hash_string(std::string_view str) noexcept
{
    static constexpr uint64_t k0 = 0x9E3779B97F4A7C15ULL;
    static constexpr uint64_t k1 = 0xBF58476D1CE4E5B9ULL;

    const char *data = str.data();
    std::size_t len = str.size();
    uint64_t h = k0 ^ (len * k1);

    while (len >= sizeof(uint64_t)) {
        uint64_t word;
        std::memcpy(&word, data, sizeof(word));
        h = (h ^ word) * k1;
        h ^= h >> 31;
        data += sizeof(word);
        len -= sizeof(word);
    }

    if (len > 0) {
        uint64_t word = 0;
        std::memcpy(&word, data, len);
        h = (h ^ word) * k1;
        h ^= h >> 31;
    }

    h ^= h >> 29;
    h *= k0;
    h ^= h >> 32;
    return h;
}

} // namespace

} // namespace ddwaf::matcher
