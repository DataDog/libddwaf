// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <iterator>
#include <set>
#include <unordered_map>
#include <vector>

#include "type_traits.hpp"

namespace ddwaf {
template <typename Key, typename T, class Compare = std::less<Key>,
    typename = std::enable_if_t<std::is_copy_constructible_v<std::remove_cv_t<std::decay_t<T>>>>>
class multi_key_map {
public:
    template <typename U,
        typename = typename std::enable_if_t<is_pair<typename U::iterator::value_type>::value,
            typename U::iterator>>
    void insert(const U &keys, const T &value)
    {
        for (const auto &key : keys) { data_[key.first][key.second].emplace(value); }
    }

    template <typename CompatKey> std::set<T> find(const std::pair<CompatKey, CompatKey> &key) const
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
    const std::set<T> &find_ref(const std::pair<CompatKey, CompatKey> &key) const
    {
        static std::set<T> empty;
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
    std::set<T> find2(const std::pair<CompatKey, CompatKey> &key0,
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

        std::set<T> result;
        std::set_intersection(set0.begin(), set0.end(), set1.begin(), set1.end(),
            std::inserter(result, result.begin()));
        return result;
    }

    template <typename U> std::set<T> multifind(const U &keys) const
    {
        std::pair<Key, Key> first = *keys.begin();

        switch (keys.size()) {
        case 0:
            return {};
        case 1:
            return find(first);
        case 2: {
            std::pair<Key, Key> second = *(++keys.begin());
            return find2(first, second);
        }
        }

        std::set<T> latest = find(first);
        if (latest.empty()) {
            return {};
        }

        std::set<T> current;
        for (const std::pair<Key, Key> key : keys) {
            const auto &next = find_ref(key);
            if (next.empty()) {
                return {};
            }

            std::set_intersection(latest.begin(), latest.end(), next.begin(), next.end(),
                std::inserter(current, current.begin()));
            std::swap(latest, current);
            current.clear();
        }

        return latest;
    }

    void clear() { data_.clear(); }
    [[nodiscard]] bool empty() const { return data_.empty(); }

protected:
    std::unordered_map<Key, std::unordered_map<Key, std::set<T>>> data_;
};

} // namespace ddwaf
