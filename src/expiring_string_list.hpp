// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ddwaf {

// A list of (string, expiration) pairs, such as the entries of a rules_data or
// exclusion_data set. All the strings are stored back to back in a single
// buffer, so a list of N entries costs two allocations rather than up to N + 1,
// and destroying it is just as cheap.
class expiring_string_list {
public:
    using value_type = std::pair<std::string_view, uint64_t>;

    expiring_string_list() = default;
    ~expiring_string_list() = default;
    expiring_string_list(const expiring_string_list &) = default;
    expiring_string_list(expiring_string_list &&) noexcept = default;
    expiring_string_list &operator=(const expiring_string_list &) = default;
    expiring_string_list &operator=(expiring_string_list &&) noexcept = default;

    expiring_string_list(std::initializer_list<value_type> list)
    {
        reserve(list.size());
        for (const auto &[str, expiration] : list) { emplace_back(str, expiration); }
    }

    void reserve(std::size_t count, std::size_t bytes = 0)
    {
        entries_.reserve(count);
        if (bytes > 0) {
            buffer_.reserve(bytes);
        }
    }

    void emplace_back(std::string_view str, uint64_t expiration)
    {
        entries_.push_back({buffer_.size(), str.size(), expiration});
        buffer_.append(str);
    }

    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    // Total length of all the strings
    [[nodiscard]] std::size_t bytes() const noexcept { return buffer_.size(); }

    [[nodiscard]] value_type operator[](std::size_t index) const noexcept
    {
        const auto &e = entries_[index];
        return {std::string_view{buffer_}.substr(e.offset, e.length), e.expiration};
    }

    class const_iterator {
    public:
        using value_type = expiring_string_list::value_type;
        using difference_type = std::ptrdiff_t;

        const_iterator() = default;
        const_iterator(const expiring_string_list *list, std::size_t index)
            : list_(list), index_(index)
        {}

        value_type operator*() const noexcept { return (*list_)[index_]; }
        const_iterator &operator++() noexcept
        {
            ++index_;
            return *this;
        }
        bool operator==(const const_iterator &other) const noexcept
        {
            return list_ == other.list_ && index_ == other.index_;
        }
        bool operator!=(const const_iterator &other) const noexcept { return !(*this == other); }

    protected:
        const expiring_string_list *list_{nullptr};
        std::size_t index_{0};
    };

    [[nodiscard]] const_iterator begin() const noexcept { return {this, 0}; }
    [[nodiscard]] const_iterator end() const noexcept { return {this, entries_.size()}; }

protected:
    struct entry {
        std::size_t offset;
        std::size_t length;
        uint64_t expiration;
    };

    std::string buffer_;
    std::vector<entry> entries_;
};

} // namespace ddwaf
