// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <set>
#include <unordered_map>
#include <vector>

#include <type_traits.hpp>

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
        for (const auto &key : keys) { data_[key].emplace(value); }
    }

    std::set<T> find(const Key &key) const
    {
        auto it = data_.find(key);
        if (it == data_.end()) {
            return {};
        }
        return it->second;
    }

    std::set<T> find2(const Key &key0, const Key &key1) const
    {
        std::set<T> result;
        auto it = data_.find(key0);
        if (it == data_.end() || it->second.empty()) {
            return {};
        }
        const auto &left = it->second;

        it = data_.find(key1);
        if (it == data_.end() || it->second.empty()) {
            return {};
        }
        const auto &right = it->second;

        std::set_intersection(left.begin(), left.end(), right.begin(), right.end(),
            std::inserter(result, result.begin()));

        return result;
    }

    std::set<T> multifind(const std::vector<Key> &keys) const
    {
        // Since this function is quite inefficient, avoid it when possible
        switch (keys.size()) {
        case 0:
            return {};
        case 1:
            return find(keys[0]);
        case 2:
            return find2(keys[0], keys[1]);
        }

        Key first = keys[0];
        std::set<T> latest = find(first);
        if (latest.empty()) {
            return {};
        }

        std::set<T> current;
        for (unsigned i = 1; i < keys.size(); i++) {
            const auto &key = keys[i];
            auto it = data_.find(key);
            if (it == data_.end() || it->second.empty()) {
                return {};
            }

            const std::set<T> &new_set = it->second;
            std::set_intersection(latest.begin(), latest.end(), new_set.begin(), new_set.end(),
                std::inserter(current, current.begin()));
            std::swap(latest, current);
            current.clear();
        }

        return latest;
    }

protected:
    std::unordered_map<Key, std::set<T>, Compare> data_;
};

} // namespace ddwaf
