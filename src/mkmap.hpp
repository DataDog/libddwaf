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

namespace ddwaf {

template <typename Key, typename T, class Compare = std::less<Key>,
    typename = std::enable_if_t<std::is_copy_constructible_v<std::remove_cv_t<std::decay_t<T>>>>>
class multi_key_map {
public:
/*    void insert(const std::vector<Key> &keys, const T &value)*/
    /*{*/
        /*for (const auto &key : keys) {*/
            /*data_[key].emplace(value);*/
        /*}*/
    /*}*/

    // TODO: SFINAE, U needs to be a class with an iterator whose value
    // can be used to construct Key
    template <typename U>
    void insert(const U &keys, const T &value) {
        for (const auto &key : keys) {
            data_[key].emplace(value);
        }
    }

    std::set<T> find(const Key &key) const
    {
        auto it = data_.find(key);
        if (it == data_.end()) {
            return {};
        }
        return it->second;
    }

    std::set<T> multifind(const std::vector<Key> &keys) const
    {
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
            std::set_intersection(latest.begin(), latest.end(), new_set.begin(),
                new_set.end(), std::inserter(current, current.begin()));
            std::swap(latest, current);
            current.clear();
        }

        return latest;
    }

protected:
    std::unordered_map<Key, std::set<T>, Compare> data_;
};

} // namespace ddwaf
