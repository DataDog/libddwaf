// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "mkmap.hpp"

namespace ddwaf {

template <typename T> class indexer {
public:
    using iterator = typename std::unordered_set<std::shared_ptr<T>>::iterator;
    using const_iterator = typename std::unordered_set<std::shared_ptr<T>>::const_iterator;

    void emplace(const std::shared_ptr<T> &item)
    {
        items_.emplace(item);
        by_id_.emplace(item->get_id(), item.get());
        by_tags_.insert(item->get_tags(), item.get());
    }

    iterator erase(const iterator &it)
    {
        const std::shared_ptr<T> &item = *it;
        by_id_.erase(item->get_id());
        by_tags_.erase(item->get_tags(), item.get());
        return items_.erase(it);
    }

    T *find_by_id(std::string_view id) const
    {
        auto it = by_id_.find(id);
        return it != by_id_.end() ? it->second : nullptr;
    }

    template <typename U> std::set<T *> find_by_tags(const U &tags) const
    {
        return by_tags_.multifind(tags);
    }

    [[nodiscard]] std::size_t size() const { return items_.size(); }

    void clear()
    {
        items_.clear();
        by_id_.clear();
        by_tags_.clear();
    }

    iterator begin() { return items_.begin(); }
    iterator end() { return items_.end(); }

    const_iterator begin() const { return items_.begin(); }
    const_iterator end() const { return items_.end(); }

    const std::unordered_set<std::shared_ptr<T>> &items() const { return items_; }

protected:
    std::unordered_set<std::shared_ptr<T>> items_;
    std::unordered_map<std::string_view, T *> by_id_;
    multi_key_map<std::string_view, T *> by_tags_;
};

} // namespace ddwaf
