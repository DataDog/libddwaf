// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <algorithm>
#include <cstddef>
#include <utility>

#include "context_allocator.hpp"

namespace ddwaf {

// Array of the caches of the elements of a collection (e.g. one per rule of a
// module), in one of two modes:
//
// - Owned: every entry is stored in the array itself, as in a vector.
// - Derived: the array is a copy-on-write view of an upstream array, e.g. the
//   cache of a subcontext over the cache of its context. Entries are read from
//   the upstream array until they're first written, at which point they're
//   copied into the derived array, so that deriving an array is O(1) and its
//   cost then depends only on the entries it writes. Those are kept sorted by
//   position, so that lookups are logarithmic and insertions in ascending
//   order, as when rules are evaluated, are amortised O(1).
//
// The upstream array of a derived array must neither be modified nor
// destroyed during the lifetime of the derived array.
template <typename T> class cache_array {
public:
    cache_array() = default;
    explicit cache_array(std::size_t size) : entries_(size) {}

    // The capacity is the number of entries expected to be written, for
    // which space is reserved on the first write.
    static cache_array derive(
        const cache_array &upstream, std::size_t capacity = default_overlay_capacity)
    {
        cache_array derived;
        derived.upstream_ = &upstream;
        derived.overlay_capacity_ = std::min(capacity, upstream.size());
        return derived;
    }

    [[nodiscard]] bool is_derived() const { return upstream_ != nullptr; }

    [[nodiscard]] std::size_t size() const
    {
        return upstream_ == nullptr ? entries_.size() : upstream_->size();
    }

    // Only applicable to owned arrays
    void resize(std::size_t size) { entries_.resize(size); }

    // Read-only access, which never copies upstream entries
    [[nodiscard]] const T &get(std::size_t pos) const
    {
        if (upstream_ == nullptr) {
            return entries_[pos];
        }

        auto it = lower_bound(pos);
        if (it != overlay_.end() && it->first == pos) {
            return it->second;
        }
        return upstream_->get(pos);
    }

    // Write access; the reference remains valid until the next call to
    // get_writable, as it may copy and insert a new entry.
    [[nodiscard]] T &get_writable(std::size_t pos)
    {
        if (upstream_ == nullptr) {
            return entries_[pos];
        }

        if (overlay_.empty()) {
            overlay_.reserve(overlay_capacity_);
        } else if (overlay_.back().first < pos) {
            // Entries are usually written in ascending order
            return overlay_.emplace_back(pos, upstream_->get(pos)).second;
        }

        auto it = lower_bound(pos);
        if (it == overlay_.end() || it->first != pos) {
            it = overlay_.emplace(it, pos, upstream_->get(pos));
        }
        return it->second;
    }

protected:
    static constexpr std::size_t default_overlay_capacity = 4;

    using overlay_type = memory::vector<std::pair<std::size_t, T>>;

    [[nodiscard]] typename overlay_type::const_iterator lower_bound(std::size_t pos) const
    {
        return std::lower_bound(overlay_.begin(), overlay_.end(), pos,
            [](const auto &entry, std::size_t value) { return entry.first < value; });
    }

    [[nodiscard]] typename overlay_type::iterator lower_bound(std::size_t pos)
    {
        return std::lower_bound(overlay_.begin(), overlay_.end(), pos,
            [](const auto &entry, std::size_t value) { return entry.first < value; });
    }

    // Owned entries
    memory::vector<T> entries_;

    // Derived arrays only: the array they derive from and the entries copied
    // from it, sorted by position
    const cache_array *upstream_{nullptr};
    overlay_type overlay_;
    std::size_t overlay_capacity_{default_overlay_capacity};
};

} // namespace ddwaf
