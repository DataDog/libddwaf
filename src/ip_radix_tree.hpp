// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "ip_utils.hpp"

namespace ddwaf {

// An immutable set of IP networks, each with an expiration timestamp, stored
// as path-compressed binary radix trees (the structure of the radixlib tree
// ip_match used before the flat range table): every network is a node at the
// depth given by its prefix length, and "glue" nodes join the subtrees of
// networks which diverge below them.
//
// Networks inside the IPv4-mapped range ::ffff:0:0/96 (IPv4 networks, which
// make up most real blocklists) are kept in a separate tree with 32-bit keys,
// all other networks in a tree with 128-bit keys. The trees are built from the
// networks sorted in preorder, and their nodes are stored in preorder in one
// vector per tree: the left child of a node, if any, is the next node, so a
// node only holds the index of its right child. An IPv4 node takes 16 bytes,
// an IPv6 node 28 bytes, and destroying a tree frees a single block.
//
// The lookup semantics are those of radixlib: among all the networks
// containing an address, the one with the latest expiration wins, an
// expiration of 0 meaning that the network never expires; a network inserted
// more than once keeps its latest expiration.
class ip_radix_tree {
public:
    // A 128-bit address as two big-endian halves (MSVC has no __int128)
    struct uint128 {
        uint64_t hi;
        uint64_t lo;

        bool operator==(const uint128 &) const = default;
    };

    class builder {
    public:
        void reserve(std::size_t size) { v4_networks_.reserve(size); }

        // Adds a network, i.e. an IPv6 (or IPv4-mapped) address and its prefix
        // length (ipaddr::mask, between 0 and 128), as produced by parse_cidr or
        // parse_network.
        // Bits beyond the prefix length are ignored. An expiration of 0 means
        // that the network never expires.
        void insert(const ipaddr &network, uint64_t expiration);

        ip_radix_tree build();

    private:
        // IPv4 network (from the IPv4-mapped range) with its sort key: the
        // IPv4 address << 8 | the IPv4 prefix length. Sorting by this key orders
        // the networks in preorder.
        struct v4_network {
            uint64_t key;
            uint64_t expiration;
        };

        struct v6_network {
            uint128 address;
            uint64_t expiration;
            unsigned prefix_len;
        };

        std::vector<v4_network> v4_networks_;
        std::vector<v6_network> v6_networks_;
    };

    ip_radix_tree() = default;

    // Returns the latest expiration among the networks containing the given
    // IPv6 (or IPv4-mapped) address, where 0 means that one of them never
    // expires; or nullopt if no network contains it. The mask and type of the
    // address are ignored.
    //
    // Expirations are kept with 54 bits: a later expiration (more than 500
    // million years from now) is returned as 0, which has the same effect.
    [[nodiscard]] std::optional<uint64_t> find(const ipaddr &ip) const;

    [[nodiscard]] bool empty() const { return v4_.empty() && v6_.empty(); }

    // Testing helpers: number of nodes (networks plus glue nodes) and bytes
    // used by the nodes
    [[nodiscard]] std::size_t node_count() const { return v4_.size() + v6_.size(); }
    [[nodiscard]] std::size_t memory_usage() const
    {
        return v4_.memory_usage() + v6_.memory_usage();
    }

    // Internally, a network that never expires has the maximum expiration, so
    // that expirations can be combined with max(), and an expiration of 0
    // marks a glue node (or, as a lookup result, no network).
    static constexpr uint64_t no_network = 0;
    static constexpr uint64_t never_expires = (uint64_t{1} << 54) - 1;

    template <typename Key> class tree {
    public:
        struct network {
            Key key; // host bits cleared
            unsigned prefix_len;
            uint64_t expiration; // internal expiration
        };

        // Builds the tree from `count` networks, network_at(i) returning the
        // i-th, in preorder: by address, and shorter prefixes first for the
        // same address. Duplicate networks are therefore adjacent.
        template <typename NetworkAt> void build(std::size_t count, NetworkAt &&network_at);

        // Latest (internal) expiration among the networks containing the
        // address, or no_network.
        [[nodiscard]] uint64_t find(Key address) const;

        [[nodiscard]] bool empty() const { return nodes_.empty(); }
        [[nodiscard]] std::size_t size() const { return nodes_.size(); }
        [[nodiscard]] std::size_t memory_usage() const { return nodes_.capacity() * sizeof(node); }

    private:
        static constexpr uint32_t nil = UINT32_MAX;

        // A node of the final tree, in preorder. The key is stored as 32-bit
        // words so that nodes only need 4-byte alignment.
        struct node {
            // Network address; the bits from bit() onwards are zero
            std::array<uint32_t, sizeof(Key) / sizeof(uint32_t)> key;
            // Index of the right child, if has_right()
            uint32_t right;
            // expiration << 10 | has_left << 9 | has_right << 8 | bit
            std::array<uint32_t, 2> meta;

            [[nodiscard]] uint64_t packed() const { return (uint64_t{meta[1]} << 32) | meta[0]; }
            [[nodiscard]] unsigned bit() const { return meta[0] & 0xff; }
            [[nodiscard]] bool has_right() const { return (meta[0] & 0x100) != 0; }
            [[nodiscard]] bool has_left() const { return (meta[0] & 0x200) != 0; }
            [[nodiscard]] uint64_t expiration() const { return packed() >> 10; }
        };

        std::vector<node> nodes_;
    };

private:
    tree<uint32_t> v4_;
    tree<uint128> v6_;
    // Latest expiration among the networks of v6_ which contain the IPv4-mapped
    // range, and therefore every IPv4 address
    uint64_t v4_base_{no_network};
};

} // namespace ddwaf
