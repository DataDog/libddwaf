// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

#include "ip_radix_tree.hpp"
#include "ip_utils.hpp"

namespace ddwaf {

namespace {

using uint128 = ip_radix_tree::uint128;

// Bit operations on the keys of the trees. Bits are numbered from the most
// significant one, which is bit 0.
template <typename Key> struct key_traits;

template <> struct key_traits<uint32_t> {
    static constexpr unsigned bits = 32;

    // Value of bit i, for i < 32
    static unsigned bit(uint32_t key, unsigned i) { return (key >> (31 - i)) & 1U; }

    // The first `len` bits of the key, the others cleared
    static uint32_t prefix(uint32_t key, unsigned len)
    {
        return static_cast<uint32_t>(key & (UINT64_MAX << (32 - len)));
    }

    // Number of leading bits on which a and b agree
    static unsigned common_prefix_len(uint32_t a, uint32_t b)
    {
        return static_cast<unsigned>(std::countl_zero(a ^ b));
    }

    // Whether the first `len` bits of a and b are equal
    static bool same_prefix(uint32_t a, uint32_t b, unsigned len)
    {
        return prefix(a ^ b, len) == 0;
    }

    static void store(uint32_t key, std::array<uint32_t, 1> &words) { words[0] = key; }
    static uint32_t load(const std::array<uint32_t, 1> &words) { return words[0]; }
};

template <> struct key_traits<uint128> {
    static constexpr unsigned bits = 128;

    static unsigned bit(const uint128 &key, unsigned i)
    {
        return i < 64 ? (key.hi >> (63 - i)) & 1U : (key.lo >> (127 - i)) & 1U;
    }

    static uint64_t half_prefix_mask(unsigned len)
    {
        return len == 0 ? 0 : (len >= 64 ? UINT64_MAX : UINT64_MAX << (64 - len));
    }

    static uint128 prefix(const uint128 &key, unsigned len)
    {
        return {.hi = key.hi & half_prefix_mask(len),
            .lo = key.lo & half_prefix_mask(len > 64 ? len - 64 : 0)};
    }

    static unsigned common_prefix_len(const uint128 &a, const uint128 &b)
    {
        if (a.hi != b.hi) {
            return static_cast<unsigned>(std::countl_zero(a.hi ^ b.hi));
        }
        return 64 + static_cast<unsigned>(std::countl_zero(a.lo ^ b.lo));
    }

    static bool same_prefix(const uint128 &a, const uint128 &b, unsigned len)
    {
        const uint128 diff = prefix({.hi = a.hi ^ b.hi, .lo = a.lo ^ b.lo}, len);
        return (diff.hi | diff.lo) == 0;
    }

    static void store(const uint128 &key, std::array<uint32_t, 4> &words)
    {
        words[0] = static_cast<uint32_t>(key.hi >> 32);
        words[1] = static_cast<uint32_t>(key.hi);
        words[2] = static_cast<uint32_t>(key.lo >> 32);
        words[3] = static_cast<uint32_t>(key.lo);
    }

    static uint128 load(const std::array<uint32_t, 4> &words)
    {
        return {.hi = (uint64_t{words[0]} << 32) | words[1],
            .lo = (uint64_t{words[2]} << 32) | words[3]};
    }
};

uint64_t load_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(uint64_t); ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        value = (value << 8) | bytes[i];
    }
    return value;
}

constexpr uint64_t v4_mapped_prefix = 0xffffULL << 32;

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

void ip_radix_tree::builder::insert(const ipaddr &network, uint64_t expiration)
{
    const unsigned prefix_len = network.mask > 128 ? 128 : network.mask;
    expiration = expiration == 0 ? never_expires : std::min(expiration, never_expires);

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    const uint128 address{.hi = load_be64(network.data), .lo = load_be64(network.data + 8)};
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

    if (address.hi == 0 && (address.lo >> 32) == 0xffff && prefix_len >= 96) {
        const unsigned v4_prefix_len = prefix_len - 96;
        const uint32_t v4_address = key_traits<uint32_t>::prefix(
            static_cast<uint32_t>(address.lo & 0xffffffff), v4_prefix_len);
        v4_networks_.push_back(
            {(static_cast<uint64_t>(v4_address) << 8) | v4_prefix_len, expiration});
        return;
    }

    v6_networks_.push_back(
        {key_traits<uint128>::prefix(address, prefix_len), expiration, prefix_len});
}

ip_radix_tree ip_radix_tree::builder::build()
{
    ip_radix_tree result;

    radix_sort(v4_networks_);
    result.v4_.build(v4_networks_.size(), [this](std::size_t i) {
        const auto &net = v4_networks_[i];
        return ip_radix_tree::tree<uint32_t>::network{.key = static_cast<uint32_t>(net.key >> 8),
            .prefix_len = static_cast<unsigned>(net.key & 0xff),
            .expiration = net.expiration};
    });

    std::sort(
        v6_networks_.begin(), v6_networks_.end(), [](const v6_network &l, const v6_network &r) {
            if (l.address.hi != r.address.hi) {
                return l.address.hi < r.address.hi;
            }
            if (l.address.lo != r.address.lo) {
                return l.address.lo < r.address.lo;
            }
            return l.prefix_len < r.prefix_len;
        });
    result.v6_.build(v6_networks_.size(), [this](std::size_t i) {
        const auto &net = v6_networks_[i];
        return ip_radix_tree::tree<uint128>::network{
            .key = net.address, .prefix_len = net.prefix_len, .expiration = net.expiration};
    });

    result.v4_base_ = result.v6_.find({.hi = 0, .lo = v4_mapped_prefix});

    v4_networks_ = {};
    v6_networks_ = {};
    return result;
}

std::optional<uint64_t> ip_radix_tree::find(const ipaddr &ip) const
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    const uint128 address{.hi = load_be64(ip.data), .lo = load_be64(ip.data + 8)};
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

    uint64_t expiration;
    if (address.hi == 0 && (address.lo >> 32) == 0xffff) {
        expiration = std::max(v4_base_, v4_.find(static_cast<uint32_t>(address.lo & 0xffffffff)));
    } else {
        expiration = v6_.find(address);
    }

    if (expiration == no_network) {
        return std::nullopt;
    }
    return expiration == never_expires ? 0 : expiration;
}

template <typename Key>
template <typename NetworkAt>
void ip_radix_tree::tree<Key>::build(std::size_t count, NetworkAt &&network_at)
{
    using traits = key_traits<Key>;
    static_assert(sizeof(node) == sizeof(Key) + 12 && alignof(node) == alignof(uint32_t));

    if (count == 0) {
        return;
    }
    // A tree with n networks has at most n - 1 glue nodes
    if (count > (nil / 2)) {
        throw std::length_error("too many networks in ip_radix_tree");
    }

    // The networks come in preorder, so the parent of each one is on the path
    // from the root to the previous one: it is the deepest node of that path
    // containing the new network, and the nodes below it will receive no other
    // descendant. If the new network diverges from the subtree of the last
    // node removed from the path (its sibling) below the parent, a glue node is
    // needed at the bit where they diverge, with the sibling's subtree on its
    // left and the new network on its right.
    //
    // In preorder, that glue node comes before the sibling's subtree, which
    // is already built. The tree is therefore built in two passes over the
    // networks: the first one runs this algorithm on the path alone, counting
    // for each network the glue nodes which will precede it (those of which it
    // is the leftmost network) and recording where it is attached; the second
    // one places every node directly at its final position and links it.
    struct path_node {
        Key key;
        uint32_t bit;
        uint32_t leftmost; // index of the first network of its subtree
        uint32_t position; // in nodes_ (second pass only)
    };
    std::array<path_node, traits::bits + 1> path{};
    std::size_t depth = 0;

    // Per network: the number of glue nodes preceding it (first pass), then
    // its position, then the position of the next glue node preceding it
    // (second pass). Duplicates of the previous network are marked.
    static constexpr uint32_t duplicate = nil;
    std::vector<uint32_t> slot(count);

    // Per network, what the first pass found, so that the second one only
    // needs to repeat the changes to the path: its depth once the nodes not
    // containing the network are removed, and how the network is attached.
    struct step {
        enum kind_type : uint8_t {
            child,       // child of the previous network (or root)
            right_child, // right child of the network at the end of the path
            glue,        // right child of a new glue node, at bit `split`,
                         // whose left child is the subtree of `leftmost`
        };
        uint32_t leftmost;
        uint8_t depth;
        kind_type kind;
        uint8_t split;
    };
    std::vector<step> steps(count);

    for (std::size_t i = 0; i < count; ++i) {
        const auto [key, len, expiration] = network_at(i);
        // The last node of the path is the previous network
        if (depth > 0 && path[depth - 1].bit == len && path[depth - 1].key == key) {
            slot[i] = duplicate;
            continue;
        }

        // Remove the nodes which do not contain the network; the last one
        // removed is its sibling
        const path_node *sibling = nullptr;
        while (depth > 0) {
            const path_node &n = path[depth - 1];
            if (n.bit < len && traits::same_prefix(key, n.key, n.bit)) {
                break;
            }
            sibling = &path[--depth];
        }

        step &s = steps[i];
        s.depth = static_cast<uint8_t>(depth);
        s.kind = step::child;
        if (sibling != nullptr) {
            const unsigned split = traits::common_prefix_len(key, sibling->key);
            assert(split < len && split < sibling->bit);
            s.split = static_cast<uint8_t>(split);
            if (depth > 0 && path[depth - 1].bit == split) {
                s.kind = step::right_child;
            } else {
                s.kind = step::glue;
                s.leftmost = sibling->leftmost;
                ++slot[s.leftmost];
                path[depth++] = {traits::prefix(key, split), split, s.leftmost, 0};
            }
        }
        path[depth++] = {key, len, static_cast<uint32_t>(i), 0};
    }

    // Positions: each network follows the glue nodes preceding it
    uint32_t total = 0;
    for (auto &s : slot) {
        if (s != duplicate) {
            total += s;
            s = total++;
        }
    }

    nodes_.resize(total);
    auto set_node = [this](uint32_t position, const Key &key, unsigned bit, uint64_t expiration,
                        uint64_t flags) -> node & {
        node &n = nodes_[position];
        traits::store(key, n.key);
        n.right = nil;
        const uint64_t packed = (expiration << 10) | flags | bit;
        n.meta[0] = static_cast<uint32_t>(packed);
        n.meta[1] = static_cast<uint32_t>(packed >> 32);
        return n;
    };
    static constexpr uint64_t has_left = 0x200;
    static constexpr uint64_t has_right = 0x100;

    depth = 0;
    // Position of the previous network: the subtree of the next network
    // starts right after it, with the glue nodes preceding that network
    uint32_t previous = nil;
    for (std::size_t i = 0; i < count; ++i) {
        const auto [key, len, expiration] = network_at(i);
        if (slot[i] == duplicate) {
            // Duplicate network: it can only extend the expiration
            node &n = nodes_[path[depth - 1].position];
            const uint64_t packed = n.packed();
            const uint64_t extended = std::max(packed >> 10, expiration) << 10 | (packed & 0x3ff);
            n.meta[0] = static_cast<uint32_t>(extended);
            n.meta[1] = static_cast<uint32_t>(extended >> 32);
            continue;
        }

        // First node of the subtree of the new network
        const uint32_t subtree = previous == nil ? 0 : previous + 1;
        const uint32_t position = slot[i]--;
        set_node(position, key, len, expiration, 0);

        const step &s = steps[i];
        depth = s.depth;
        if (s.kind == step::child) {
            // The parent, if any, is the previous network, a leaf so far
            if (depth > 0) {
                node &parent = nodes_[path[depth - 1].position];
                if (traits::bit(key, path[depth - 1].bit) == 0) {
                    parent.meta[0] |= has_left;
                } else {
                    parent.meta[0] |= has_right;
                    parent.right = subtree;
                }
            }
        } else if (s.kind == step::right_child) {
            // The parent is a network whose only child is the sibling, on the
            // left
            node &parent = nodes_[path[depth - 1].position];
            assert((parent.meta[0] & has_right) == 0);
            parent.meta[0] |= has_right;
            parent.right = subtree;
        } else {
            // The glue node takes the place of the sibling's subtree, whose
            // position is that of the first glue node preceding the sibling's
            // leftmost network: the parent's link to it remains valid.
            const uint32_t glue = slot[s.leftmost]--;
            const Key glue_key = traits::prefix(key, s.split);
            node &n = set_node(glue, glue_key, s.split, no_network, has_left | has_right);
            n.right = subtree;
            path[depth++] = {glue_key, s.split, s.leftmost, glue};
        }
        path[depth++] = {key, len, static_cast<uint32_t>(i), position};
        previous = position;
    }
}

template <typename Key> uint64_t ip_radix_tree::tree<Key>::find(Key address) const
{
    using traits = key_traits<Key>;

    if (nodes_.empty()) {
        return no_network;
    }

    // Every node below a node which doesn't contain the address has a longer
    // prefix of that node's address, so the search stops at the first one.
    uint64_t expiration = no_network;
    std::size_t index = 0;
    while (true) {
        const node &n = nodes_[index];
        const unsigned bit = n.bit();
        if (!traits::same_prefix(address, traits::load(n.key), bit)) {
            break;
        }
        expiration = std::max(expiration, n.expiration());
        if (bit == traits::bits) {
            break;
        }
        if (traits::bit(address, bit) == 0) {
            if (!n.has_left()) {
                break;
            }
            ++index;
        } else {
            if (!n.has_right()) {
                break;
            }
            index = n.right;
        }
    }
    return expiration;
}

template class ip_radix_tree::tree<uint32_t>;
template class ip_radix_tree::tree<uint128>;

} // namespace ddwaf
