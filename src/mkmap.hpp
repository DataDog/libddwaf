// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <functional>
#include <iterator>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "traits.hpp"

namespace ddwaf {

// A map from (key, value) pairs, e.g. tags, to the set of items carrying them.
//
// Each set is a sorted vector without duplicates, ordered by std::less<T>, so
// that lookups and intersections are linear scans over contiguous memory and
// building the map does not allocate one node per item and tag. Results are
// returned in the same order.
template <typename Key, typename T, class Compare = std::less<Key>>
    requires std::is_copy_constructible_v<std::decay_t<T>>
class multi_key_map {
public:
    using set_type = std::vector<T>;

    template <typename U>
    void insert(const U &keys, const T &value)
        requires is_pair<typename U::iterator::value_type>::value
    {
        for (const auto &key : keys) { sorted_insert(data_[key.first][key.second], value); }
    }

    template <typename U>
    void erase(const U &keys, const T &value)
        requires is_pair<typename U::iterator::value_type>::value
    {
        for (const auto &key : keys) { sorted_erase(data_[key.first][key.second], value); }
    }

    template <typename CompatKey> set_type find(const std::pair<CompatKey, CompatKey> &key) const
    {
        auto first_it = data_.find(key.first);
        if (first_it == data_.end()) {
            return {};
        }

        const auto &second_data = first_it->second;
        auto second_it = second_data.find(key.second);
        if (second_it == second_data.end()) {
            return {};
        }

        return second_it->second;
    }

    template <typename CompatKey>
    const set_type &find_ref(const std::pair<CompatKey, CompatKey> &key) const
    {
        static const set_type empty;
        auto first_it = data_.find(Key(key.first));
        if (first_it == data_.end()) {
            return empty;
        }

        const auto &second_data = first_it->second;
        auto second_it = second_data.find(Key(key.second));
        if (second_it == second_data.end()) {
            return empty;
        }

        return second_it->second;
    }

    template <typename CompatKey>
    set_type find2(const std::pair<CompatKey, CompatKey> &key0,
        const std::pair<CompatKey, CompatKey> &key1) const
    {
        const auto &set0 = find_ref(key0);
        if (set0.empty()) {
            return {};
        }

        const auto &set1 = find_ref(key1);
        if (set1.empty()) {
            return {};
        }

        set_type result;
        result.reserve(std::min(set0.size(), set1.size()));
        std::set_intersection(set0.begin(), set0.end(), set1.begin(), set1.end(),
            std::back_inserter(result), item_less{});
        return result;
    }

    template <typename U> set_type multifind(const U &keys) const
    {
        const std::pair<Key, Key> first = *keys.begin();

        switch (keys.size()) {
        case 0:
            return {};
        case 1:
            return find(first);
        case 2: {
            const std::pair<Key, Key> second = *(++keys.begin());
            return find2(first, second);
        }
        }

        set_type latest = find(first);
        if (latest.empty()) {
            return {};
        }

        set_type current;
        current.reserve(latest.size());
        for (const std::pair<Key, Key> key : keys) {
            const auto &next = find_ref(key);
            if (next.empty()) {
                return {};
            }

            std::set_intersection(latest.begin(), latest.end(), next.begin(), next.end(),
                std::back_inserter(current), item_less{});
            std::swap(latest, current);
            current.clear();
        }

        return latest;
    }

    void clear() { data_.clear(); }
    [[nodiscard]] bool empty() const { return data_.empty(); }

protected:
    using item_less = std::less<T>;

    static void sorted_insert(set_type &set, const T &value)
    {
        // Items are usually inserted in increasing order (e.g. pointers to the
        // elements of a vector), in which case this is an append.
        if (set.empty() || item_less{}(set.back(), value)) {
            set.emplace_back(value);
            return;
        }

        auto it = std::lower_bound(set.begin(), set.end(), value, item_less{});
        if (it == set.end() || item_less{}(value, *it)) {
            set.insert(it, value);
        }
    }

    static void sorted_erase(set_type &set, const T &value)
    {
        auto it = std::lower_bound(set.begin(), set.end(), value, item_less{});
        if (it != set.end() && !item_less{}(value, *it)) {
            set.erase(it);
        }
    }

    std::unordered_map<Key, std::unordered_map<Key, set_type>> data_;
};

} // namespace ddwaf
