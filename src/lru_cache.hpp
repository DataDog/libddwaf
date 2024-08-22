// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>

#include "traits.hpp"

namespace ddwaf {

template <typename KeyType, typename DurationType, typename DataType, typename ConstructorType>
    requires is_duration<DurationType>
class lru_cache {
public:
    explicit lru_cache(ConstructorType constructor, std::size_t max_index_size = 32)
        : constructor_(std::move(constructor)), max_index_size_(max_index_size)
    {}


    template <typename CompatKeyType>
        requires std::is_constructible_v<CompatKeyType, KeyType>
    DataType& emplace_or_retrieve(CompatKeyType key, DurationType timepoint)
    {
        auto it = index_.find(key);
        if (it == index_.end()) {
            if (index_.size() == max_index_size_) {
                remove_oldest_entry(timepoint);
            }


            auto [new_it, res] = index_.emplace(KeyType{key}, cache_entry{timepoint, constructor_()});
            if (!res) {
                throw std::out_of_range("failed to add element to cache");
            }
            return new_it->second.data;
        }

         it->second.latest_timepoint = std::max(timepoint, it->second.latest_timepoint);

        return it->second.data;
    }

protected:
    struct cache_entry {
        DurationType latest_timepoint;
        DataType data;
    };

    void remove_oldest_entry(DurationType timepoint)
    {
        using iterator_type = typename decltype(index_)::iterator;

        DurationType max_delta{0};
        iterator_type oldest_it;
        for (auto it = index_.begin(); it != index_.end(); ++it) {
            auto window_last = it->second.latest_timepoint;
            auto delta = timepoint - window_last;
            if (delta > max_delta) {
                max_delta = delta;
                oldest_it = it;
            }
        }

        index_.erase(oldest_it);
    }

    ConstructorType constructor_;
    std::size_t max_index_size_{};
    std::map<KeyType, cache_entry, std::less<>> index_;
};

template <typename DataType, typename ConstructorType>
using lru_cache_ms = lru_cache<std::string, std::chrono::milliseconds, DataType, ConstructorType>;

} // namespace ddwaf
