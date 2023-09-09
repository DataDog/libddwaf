// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "memory_resource.hpp"
#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf::memory {
extern thread_local std::pmr::memory_resource *local_memory_resource;

inline std::pmr::memory_resource *get_local_memory_resource() { return local_memory_resource; }

inline void set_local_memory_resource(std::pmr::memory_resource *mr) { local_memory_resource = mr; }

// The null memory resource is used as the default onef or the static thread
// local memory resource. Only exposed for testing purposes.
class null_memory_resource final : public std::pmr::memory_resource {
    void *do_allocate(size_t /*bytes*/, size_t /*alignment*/) override { throw std::bad_alloc(); }
    void do_deallocate(void * /*p*/, size_t /*bytes*/, size_t /*alignment*/) noexcept override {}
    [[nodiscard]] bool do_is_equal(const memory_resource &other) const noexcept override
    {
        return this == &other;
    }
};

// The memory resource guard replaces the current static thread local memory
// resource with the user provided one on construction and reverts it back on
// destruction.
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

// The context allocator uses the static thread local memory resource to
// allocate memory for STL objecs. The thread local memory resource has to be
// set before constructing, modifying or destroying an object using the
// context allocator, otherwise allocations should fail as the default thread
// local resource is the null resource.
// As the name suggests, the purpose of the context_allocator and the static
// thread local memory resources is to optimise allocations and deallocations
// within the context lifecycle, reduce global allocator contention.
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

// Required STL type definitions with context allocator
using string = std::basic_string<char, std::char_traits<char>, context_allocator<char>>;

template <typename T> using vector = std::vector<T, context_allocator<T>>;

template <class T> using list = std::list<T, context_allocator<T>>;

template <class Key, class T, class Hash = std::hash<Key>, class Pred = std::equal_to<Key>>
using unordered_map =
    ::absl::flat_hash_map<Key, T, Hash, Pred, context_allocator<std::pair<const Key, T>>>;

template <class T, class Hash = std::hash<T>, class Pred = std::equal_to<T>>
using unordered_set = ::absl::flat_hash_set<T, Hash, Pred, context_allocator<T>>;

} // namespace ddwaf::memory
