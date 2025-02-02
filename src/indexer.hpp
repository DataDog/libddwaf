// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include "mkmap.hpp"

namespace ddwaf {

template <typename T, template <typename, typename...> class PtrType = std::shared_ptr>
class indexer {
public:
    using Ptr = PtrType<T>;
    using iterator = typename std::vector<Ptr>::iterator;
    using const_iterator = typename std::vector<Ptr>::const_iterator;

    void emplace(const Ptr &item)
    {
        items_.emplace_back(item);
        by_id_.emplace(item->get_id(), item.get());
        by_tags_.insert(item->get_tags(), item.get());
    }

    iterator erase(iterator &it)
    {
        auto &item = *it;
        by_tags_.erase(item->get_tags(), item.get());
        by_id_.erase(item->get_id());
        return items_.erase(it);
    }

    void erase(std::string_view id)
    {
        iterator it;
        for (it = items_.begin(); it != items_.end(); ++it) {
            if (id == (*it)->get_id()) {
                break;
            }
        }

        if (it == items_.end()) {
            return;
        }

        erase(it);
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

    [[nodiscard]] std::size_t size() const { return items_.size(); }
    [[nodiscard]] bool empty() const { return items_.empty(); }

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

    const std::vector<Ptr> &items() const { return items_; }

protected:
    std::vector<Ptr> items_;
    std::unordered_map<std::string_view, T *> by_id_;
    multi_key_map<std::string, T *> by_tags_;
};

} // namespace ddwaf
