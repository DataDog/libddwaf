// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "ip_utils.hpp"

namespace ddwaf {

// An immutable set of IPv6 networks (IPv4 networks are expected in their
// IPv4-mapped form), each with an expiration timestamp.
//
// The networks are flattened at build time into a sorted partition of the
// 128-bit address space: each entry covers the addresses from its start up to
// the start of the next entry, and holds the latest expiration among all the
// networks containing those addresses (or nothing, for addresses outside all
// networks). A lookup is therefore a single binary search, the whole table is
// one contiguous allocation, and building it takes a sort and a linear sweep.
//
// The lookup semantics are those of the radix tree this replaces: among all the
// networks containing an address, the one with the latest expiration wins, an
// expiration of 0 meaning that the network never expires.
class ip_range_table {
    // A 128-bit address as two big-endian halves, ordered numerically
    struct address {
        uint64_t hi;
        uint64_t lo;

        auto operator<=>(const address &) const = default;
    };

public:
    class builder {
    public:
        void reserve(std::size_t size) { v4_networks_.reserve(size); }

        // Adds a network, i.e. an IPv6 (or IPv4-mapped) address and its prefix
        // length (ipaddr::mask, between 0 and 128), as produced by parse_cidr.
        // Bits beyond the prefix length are ignored. An expiration of 0 means
        // that the network never expires.
        void insert(const ipaddr &network, uint64_t expiration);

        ip_range_table build();

    private:
        struct network {
            address first;
            address last;
            uint64_t expiration;
        };

        // Networks within the IPv4-mapped range ::ffff:0:0/96, which are the
        // vast majority in practice, are kept apart with a compact sort key
        // (IPv4 address << 8 | IPv4 prefix length), so that they can be
        // radix-sorted instead of comparison-sorted on 128-bit addresses.
        struct v4_network {
            uint64_t key;
            uint64_t expiration;
        };

        static network to_network(const v4_network &net);

        std::vector<network> networks_;
        std::vector<v4_network> v4_networks_;
    };

    ip_range_table() = default;

    // Returns the latest expiration among the networks containing the given
    // IPv6 (or IPv4-mapped) address, where 0 means that one of them never
    // expires; or nullopt if no network contains it. The mask of the address
    // is ignored.
    [[nodiscard]] std::optional<uint64_t> find(const ipaddr &ip) const;

    [[nodiscard]] bool empty() const { return entries_.empty(); }
    // Number of entries in the flattened partition (not the number of networks)
    [[nodiscard]] std::size_t size() const { return entries_.size(); }

private:
    // Internally, a network that never expires has the maximum expiration, so
    // that the expiration of overlapping networks can be combined with max(),
    // and an expiration of 0 marks addresses which aren't in any network.
    static constexpr uint64_t no_network = 0;
    static constexpr uint64_t never_expires = UINT64_MAX;

    struct entry {
        address start;
        uint64_t expiration;
    };

    explicit ip_range_table(std::vector<entry> entries) : entries_(std::move(entries)) {}

    std::vector<entry> entries_;
};

} // namespace ddwaf
