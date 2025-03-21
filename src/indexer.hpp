// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <unordered_map>

#include "mkmap.hpp"

namespace ddwaf {

template <typename T> class indexer {
public:
    using iterator = typename std::unordered_map<std::string_view, T *>::iterator;
    using const_iterator = typename std::unordered_map<std::string_view, T *>::const_iterator;

    void emplace(T *item)
    {
        by_id_.emplace(item->get_id(), item);
        by_tags_.insert(item->get_tags(), item);
    }

    [[nodiscard]] bool contains(std::string_view id) const { return by_id_.contains(id); }

    T *find_by_id(std::string_view id) const
    {
        auto it = by_id_.find(id);
        return it != by_id_.end() ? it->second : nullptr;
    }

    template <typename U> std::set<T *> find_by_tags(const U &tags) const
    {
        return by_tags_.multifind(tags);
    }

    [[nodiscard]] std::size_t size() const { return by_id_.size(); }
    [[nodiscard]] bool empty() const { return by_id_.empty(); }

    void clear()
    {
        by_id_.clear();
        by_tags_.clear();
    }

    iterator begin() { return by_id_.begin(); }
    iterator end() { return by_id_.end(); }

    const_iterator begin() const { return by_id_.begin(); }
    const_iterator end() const { return by_id_.end(); }

protected:
    std::unordered_map<std::string_view, T *> by_id_;
    multi_key_map<std::string, T *> by_tags_;
};

} // namespace ddwaf
