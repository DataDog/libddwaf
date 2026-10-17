// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <unordered_map>
#include <vector>

namespace ddwaf {

// The indexed multivector is a container which stores multiple vectors indexed
// by a key. The main purpose of the indexed multivector is to allow the
// iteration of all vectors as a single vector, as well as the ability to remove
// individual ones as needed. Note that the vector the insertion order isn't
// preserved. The per-key container defaults to std::vector<T>, but any
// container with size() and forward const iterators can be used.
template <typename Key, typename T, typename Container = std::vector<T>> class indexed_multivector {
public:
    indexed_multivector() = default;
    void emplace(Key key, Container element)
    {
        total_size_ += element.size();
        data_.emplace(std::move(key), std::move(element));
    }
    void erase(const Key &key)
    {
        auto it = data_.find(key);
        if (it != data_.end()) {
            total_size_ -= it->second.size();
            data_.erase(it);
        }
    }
    [[nodiscard]] bool empty() const { return data_.empty(); }
    [[nodiscard]] std::size_t size() const { return total_size_; }

    class const_iterator {
    public:
        using index_iterator_type = typename std::unordered_map<Key, Container>::const_iterator;
        using item_iterator_type = typename Container::const_iterator;
        const_iterator(
            // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
            index_iterator_type index_it, index_iterator_type end_index_it,
            item_iterator_type item_it)
            : index_it_(index_it), end_index_it_(end_index_it), item_it_(item_it)
        {
            skip_empty();
        }

        const_iterator &operator++()
        {
            ++item_it_;
            skip_empty();
            return *this;
        }

        bool operator==(const_iterator other) const
        {
            return index_it_ == other.index_it_ && item_it_ == other.item_it_;
        }

        bool operator!=(const_iterator other) const { return !(*this == other); }

        decltype(auto) operator*() const { return *item_it_; }

    protected:
        // Advance to the next element, skipping exhausted or empty containers
        void skip_empty()
        {
            while (index_it_ != end_index_it_ && item_it_ == index_it_->second.end()) {
                ++index_it_;
                if (index_it_ != end_index_it_) {
                    item_it_ = index_it_->second.begin();
                } else {
                    item_it_ = {};
                }
            }
        }

        index_iterator_type index_it_;
        index_iterator_type end_index_it_;
        item_iterator_type item_it_;
    };

    const_iterator begin() const
    {
        if (data_.empty()) {
            return end();
        }

        auto index_it = data_.begin();
        auto item_it = index_it->second.begin();

        return {index_it, data_.end(), item_it};
    }

    const_iterator end() const { return {data_.end(), data_.end(), {}}; }

protected:
    std::unordered_map<Key, Container> data_;
    std::size_t total_size_{0};
};
} // namespace ddwaf
