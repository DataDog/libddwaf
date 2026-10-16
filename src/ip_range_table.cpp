// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <vector>

#include "ip_range_table.hpp"
#include "ip_utils.hpp"

namespace ddwaf {

namespace {

uint64_t load_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(uint64_t); ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        value = (value << 8) | bytes[i];
    }
    return value;
}

// Mask selecting the bits of a 64-bit half which are not covered by a prefix of
// the given length, counted from the start of that half
uint64_t host_bits(unsigned prefix_len)
{
    return prefix_len >= 64 ? 0 : (UINT64_MAX >> prefix_len);
}

// LSD radix sort on the low 40 bits of `key` (the IPv4 sort key), 10 bits at a
// time, skipping the passes where all the keys have the same digit.
template <typename T> void radix_sort(std::vector<T> &items)
{
    static constexpr unsigned key_bits = 40;
    static constexpr unsigned digit_bits = 10;
    static constexpr std::size_t buckets = 1U << digit_bits;

    if (items.size() < 2) {
        return;
    }

    std::vector<T> buffer(items.size());
    std::vector<std::size_t> offsets(buckets);
    for (unsigned shift = 0; shift < key_bits; shift += digit_bits) {
        auto digit = [shift](const T &item) {
            return static_cast<std::size_t>((item.key >> shift) & (buckets - 1));
        };

        std::fill(offsets.begin(), offsets.end(), 0);
        for (const auto &item : items) { ++offsets[digit(item)]; }
        if (offsets[digit(items.front())] == items.size()) {
            continue;
        }

        std::size_t total = 0;
        for (auto &offset : offsets) {
            const std::size_t count = offset;
            offset = total;
            total += count;
        }

        for (const auto &item : items) { buffer[offsets[digit(item)]++] = item; }
        items.swap(buffer);
    }
}

} // namespace

void ip_range_table::builder::insert(const ipaddr &network, uint64_t expiration)
{
    const unsigned prefix_len = network.mask > 128 ? 128 : network.mask;
    expiration = expiration == 0 ? never_expires : expiration;

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    const uint64_t hi = load_be64(network.data);
    const uint64_t lo = load_be64(network.data + sizeof(uint64_t));
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

    if (hi == 0 && (lo >> 32) == 0xffff && prefix_len >= 96) {
        const unsigned v4_prefix_len = prefix_len - 96;
        const uint64_t v4_first = (lo & 0xffffffff) & ~host_bits(32 + v4_prefix_len);
        v4_networks_.push_back({(v4_first << 8) | v4_prefix_len, expiration});
        return;
    }

    const uint64_t hi_host = host_bits(prefix_len);
    const uint64_t lo_host = prefix_len <= 64 ? UINT64_MAX : host_bits(prefix_len - 64);

    networks_.push_back({
        .first = {.hi = hi & ~hi_host, .lo = lo & ~lo_host},
        .last = {.hi = hi | hi_host, .lo = lo | lo_host},
        .expiration = expiration,
    });
}

ip_range_table::builder::network ip_range_table::builder::to_network(const v4_network &net)
{
    static constexpr uint64_t v4_mapped_prefix = 0xffffULL << 32;
    const uint64_t v4_first = net.key >> 8;
    const unsigned v4_prefix_len = net.key & 0xff;
    return {
        .first = {.hi = 0, .lo = v4_mapped_prefix | v4_first},
        .last = {.hi = 0, .lo = v4_mapped_prefix | v4_first | host_bits(32 + v4_prefix_len)},
        .expiration = net.expiration,
    };
}

ip_range_table ip_range_table::builder::build()
{
    // Two networks are either disjoint or one contains the other. Ordering them
    // by first address, and the larger one first when they start at the same
    // address, places every network after all the networks which contain it.
    auto precedes = [](const network &l, const network &r) {
        if (l.first != r.first) {
            return l.first < r.first;
        }
        return l.last > r.last;
    };
    std::sort(networks_.begin(), networks_.end(), precedes);

    // The IPv4 sort key orders the networks the same way, as a larger network
    // starting at the same address has a shorter prefix.
    radix_sort(v4_networks_);

    std::vector<entry> entries;
    entries.reserve((networks_.size() + v4_networks_.size()) * 2);

    // Records that the expiration of the addresses from `start` onwards is
    // `expiration`. Starts are non-decreasing; a later call with the same start
    // supersedes the earlier one, and consecutive entries with the same
    // expiration are coalesced.
    auto set_from = [&entries](address start, uint64_t expiration) {
        if (!entries.empty() && entries.back().start == start) {
            entries.pop_back();
        }
        if (!entries.empty() && entries.back().expiration == expiration) {
            return;
        }
        entries.push_back({start, expiration});
    };

    // The networks containing the current position, innermost last, with their
    // effective expiration (the latest among them and the networks containing
    // them). Each one is strictly larger than the next, so there are at most
    // 129 of them.
    struct open_network {
        address first;
        address last;
        uint64_t expiration;
    };
    std::vector<open_network> open;

    static constexpr address max_address{.hi = UINT64_MAX, .lo = UINT64_MAX};
    auto close_network = [&]() {
        const address last = open.back().last;
        open.pop_back();
        if (last != max_address) {
            address next = last;
            if (++next.lo == 0) {
                ++next.hi;
            }
            set_from(next, open.empty() ? no_network : open.back().expiration);
        }
    };

    auto add_network = [&](const network &net) {
        while (!open.empty() && open.back().last < net.first) { close_network(); }

        if (!open.empty() && open.back().first == net.first && open.back().last == net.last) {
            // Duplicate network: it can only extend the expiration
            if (net.expiration > open.back().expiration) {
                open.back().expiration = net.expiration;
                set_from(net.first, net.expiration);
            }
            return;
        }

        const uint64_t expiration =
            open.empty() ? net.expiration : std::max(net.expiration, open.back().expiration);
        set_from(net.first, expiration);
        open.push_back({net.first, net.last, expiration});
    };

    // Merge the two sorted sequences
    auto it = networks_.begin();
    auto v4_it = v4_networks_.begin();
    while (it != networks_.end() || v4_it != v4_networks_.end()) {
        if (v4_it == v4_networks_.end()) {
            add_network(*it++);
            continue;
        }

        const network v4_net = to_network(*v4_it);
        if (it != networks_.end() && precedes(*it, v4_net)) {
            add_network(*it++);
        } else {
            add_network(v4_net);
            ++v4_it;
        }
    }

    while (!open.empty()) { close_network(); }

    networks_ = {};
    v4_networks_ = {};
    entries.shrink_to_fit();

    return ip_range_table{std::move(entries)};
}

std::optional<uint64_t> ip_range_table::find(const ipaddr &ip) const
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    const address addr{.hi = load_be64(ip.data), .lo = load_be64(ip.data + sizeof(uint64_t))};
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

    // The entry covering the address is the last one starting at or before it
    auto it = std::upper_bound(entries_.begin(), entries_.end(), addr,
        [](const address &value, const entry &e) { return value < e.start; });
    if (it == entries_.begin()) {
        return std::nullopt;
    }

    const uint64_t expiration = std::prev(it)->expiration;
    if (expiration == no_network) {
        return std::nullopt;
    }

    return expiration == never_expires ? 0 : expiration;
}

} // namespace ddwaf
