// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ddwaf {

// Identifies an address: target indices are small integers, assigned on first
// use, in sequence, and never reused within the process, so that they can be
// used to index arrays (e.g. in the object store).
using target_index = std::size_t;

// Virtual address registered by the engine when an event has been generated,
// rather than provided by the caller; it's included in every target_lookup.
inline constexpr std::string_view context_event_address = "waf.context.event";

// Returns the index of the address, registering it if it hasn't been seen
// before. This takes a lock, so it's meant for building rulesets (and tests);
// addresses provided at evaluation time are resolved with a target_lookup.
target_index get_target_index(std::string_view address);

// Testing helpers: take and release the lock of the registry used by
// get_target_index and get_target_lookup.
void lock_target_registry();
void unlock_target_registry();

// Immutable table resolving address names to their target index, without
// locking. It contains the addresses registered at the time of its creation
// (see get_target_lookup), therefore, every address which any component of a
// ruleset built before then can refer to.
class target_lookup {
public:
    static constexpr target_index npos = std::numeric_limits<uint32_t>::max();

    target_lookup() = default;
    // The index of each name is its position
    explicit target_lookup(std::span<const std::string_view> names);

    // Returns the index of the address or npos if it's not in the table
    [[nodiscard]] target_index find(std::string_view name) const
    {
        if (slots_.empty()) {
            return npos;
        }

        const auto h = hash(name);
        for (auto i = h & mask_;; i = (i + 1) & mask_) {
            const auto &s = slots_[i];
            if (s.index == npos) {
                return npos;
            }
            if (s.hash == h && s.length == name.size() &&
                std::string_view{names_.data() + s.offset, s.length} == name) {
                return s.index;
            }
        }
    }

    // All indices in the table are lower than its size
    [[nodiscard]] std::size_t size() const { return size_; }

    // A cheap hash for short strings, such as address names
    static uint64_t hash(std::string_view str);

protected:
    // Open addressing table with linear probing, an empty slot has index npos
    struct slot {
        uint64_t hash{0};
        uint32_t offset{0};
        uint32_t length{0};
        uint32_t index{npos};
    };

    std::vector<slot> slots_;
    std::size_t mask_{0};
    std::string names_;
    std::size_t size_{0};
};

// Returns a lookup table of all the addresses registered so far
std::shared_ptr<const target_lookup> get_target_lookup();

struct target_address {
    explicit target_address(std::string name_)
        : name(std::move(name_)), index(get_target_index(name))
    {}

    bool operator<(const target_address &o) const { return name < o.name; }
    bool operator>(const target_address &o) const { return name > o.name; }
    bool operator==(const target_address &o) const { return name == o.name; }

    std::string name;
    target_index index;
};

struct target_address_view {
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    target_address_view(const target_address &address) : name(address.name), index(address.index) {}

    bool operator<(const target_address_view &o) const { return name < o.name; }
    bool operator>(const target_address_view &o) const { return name > o.name; }
    bool operator==(const target_address_view &o) const { return name == o.name; }

    std::string_view name;
    target_index index;
};

} // namespace ddwaf

namespace std {
template <> struct hash<ddwaf::target_address> {
    size_t operator()(const ddwaf::target_address &addr) const { return addr.index; }
};

template <> struct hash<ddwaf::target_address_view> {
    size_t operator()(const ddwaf::target_address_view &addr) const { return addr.index; }
};
} // namespace std
