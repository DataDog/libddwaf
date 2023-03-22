// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "memory_resource.hpp"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf::memory {
extern thread_local std::pmr::memory_resource *local_memory_resource;

inline std::pmr::memory_resource *get_local_memory_resource() { return local_memory_resource; }

inline void set_local_memory_resource(std::pmr::memory_resource *mr) { local_memory_resource = mr; }

class memory_resource_guard {
public:
    explicit memory_resource_guard(std::pmr::memory_resource *mr) noexcept
        : old_mr_(get_local_memory_resource())
    {
        if (mr != nullptr) {
            set_local_memory_resource(mr);
        }
    }

    ~memory_resource_guard() noexcept { set_local_memory_resource(old_mr_); }

    memory_resource_guard(const memory_resource_guard &) = delete;
    memory_resource_guard(memory_resource_guard &&) = delete;
    memory_resource_guard &operator=(const memory_resource_guard &) = delete;
    memory_resource_guard &operator=(memory_resource_guard &&) = delete;

protected:
    std::pmr::memory_resource *old_mr_;
};

template <typename T = std::byte> class context_allocator {
public:
    using value_type = T;
    context_allocator() noexcept = default;
    ~context_allocator() = default;
    context_allocator(context_allocator &&) noexcept = default;
    context_allocator(const context_allocator &) = default;
    context_allocator &operator=(context_allocator &&) noexcept = default;
    context_allocator &operator=(const context_allocator &) = default;

    template <typename U>
    explicit context_allocator(const context_allocator<U> & /*other*/) noexcept
    {}

    T *allocate(std::size_t n)
    {
        auto *mr = get_local_memory_resource();
        return static_cast<T *>(mr->allocate(n * sizeof(T), alignof(T)));
    }

    void deallocate(T *p, std::size_t n) noexcept
    {
        auto *mr = get_local_memory_resource();
        mr->deallocate(p, n * sizeof(T), alignof(T));
    }

    bool operator!=(const context_allocator & /*unused*/) { return false; }
    bool operator==(const context_allocator & /*unused*/) { return true; }
};

using string = std::basic_string<char, std::char_traits<char>, context_allocator<char>>;

template <typename T> using vector = std::vector<T, context_allocator<T>>;

template <class Key, class T, class Hash = std::hash<Key>, class Pred = std::equal_to<Key>>
using unordered_map =
    std::unordered_map<Key, T, Hash, Pred, context_allocator<std::pair<const Key, T>>>;

template <class T, class Hash = std::hash<T>, class Pred = std::equal_to<T>>
using unordered_set = std::unordered_set<T, Hash, Pred, context_allocator<T>>;

} // namespace ddwaf::memory
