// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "target_address.hpp"

#ifndef _WIN32
#  include <pthread.h>
#endif

namespace ddwaf {

namespace {

// Process-wide registry of the addresses, assigning each a dense index. The
// indices are global, rather than per ruleset, as components (and the targets
// they refer to) are shared across the rulesets produced by a builder, and
// separate builders may share addresses too.
class target_registry {
public:
    // Addresses which aren't referenced by any component but are registered
    // during evaluation are known in advance, so that the store of a context
    // never needs to grow to accommodate them.
    target_registry() { intern(context_event_address); }

    target_index intern(std::string_view address)
    {
        const std::lock_guard<std::mutex> lock(mtx_);
        auto it = indices_.find(address);
        if (it != indices_.end()) {
            return it->second;
        }

        const target_index index = names_.size();
        // The deque never relocates its elements, so the key remains valid
        const std::string_view name = names_.emplace_back(address);
        indices_.emplace(name, index);
        return index;
    }

    std::shared_ptr<const target_lookup> lookup()
    {
        const std::lock_guard<std::mutex> lock(mtx_);
        if (!lookup_ || lookup_->size() != names_.size()) {
            const std::vector<std::string_view> names{names_.begin(), names_.end()};
            lookup_ = std::make_shared<const target_lookup>(names);
        }
        return lookup_;
    }

    // See registry()
    void lock_for_fork() { mtx_.lock(); }
    void unlock_after_fork() { mtx_.unlock(); }

protected:
    std::mutex mtx_;
    std::deque<std::string> names_;
    std::unordered_map<std::string_view, target_index> indices_;
    // Lookup of the current names, reused until a new address is registered
    std::shared_ptr<const target_lookup> lookup_;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
constinit target_registry *registry_instance = nullptr;

target_registry &registry()
{
    // Never destroyed, so that it remains usable while other static objects
    // are destroyed.
    static auto *instance = [] {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        registry_instance = new target_registry;
#ifndef _WIN32
        // The registry is used while building rulesets, possibly on another
        // thread than the one forking; a child forked while that thread holds
        // the lock would otherwise never be able to build one.
        pthread_atfork([] { registry_instance->lock_for_fork(); },
            [] { registry_instance->unlock_after_fork(); },
            [] { registry_instance->unlock_after_fork(); });
#endif
        return registry_instance;
    }();
    return *instance;
}

} // namespace

target_index get_target_index(std::string_view address) { return registry().intern(address); }

std::shared_ptr<const target_lookup> get_target_lookup() { return registry().lookup(); }

void lock_target_registry() { registry().lock_for_fork(); }
void unlock_target_registry() { registry().unlock_after_fork(); }

target_lookup::target_lookup(std::span<const std::string_view> names) : size_(names.size())
{
    if (names.empty()) {
        return;
    }

    // Keep the load factor at or below 50%, so that probing remains short and
    // there is always at least one empty slot to end it.
    const auto capacity = std::bit_ceil(names.size() * 2);
    slots_.resize(capacity);
    mask_ = capacity - 1;

    std::size_t total_length = 0;
    for (auto name : names) { total_length += name.size(); }
    names_.reserve(total_length);

    for (std::size_t index = 0; index < names.size(); ++index) {
        const auto name = names[index];
        const auto h = hash(name);
        auto i = h & mask_;
        while (slots_[i].index != npos) { i = (i + 1) & mask_; }

        slots_[i] = {.hash = h,
            .offset = static_cast<uint32_t>(names_.size()),
            .length = static_cast<uint32_t>(name.size()),
            .index = static_cast<uint32_t>(index)};
        names_.append(name);
    }
}

uint64_t target_lookup::hash(std::string_view str)
{
    // Multiplicative mixing of 8-byte words, followed by a finalizer, which
    // is plenty for a table at most half full; collisions only cost a
    // comparison, as the names are compared in full anyway.
    constexpr uint64_t mul = 0x9e3779b97f4a7c15ULL;
    const auto mix = [](uint64_t h, uint64_t word) {
        h = (h ^ word) * mul;
        return h ^ (h >> 32);
    };

    uint64_t h = str.size() * mul;
    const char *data = str.data();
    std::size_t remaining = str.size();
    for (; remaining >= sizeof(uint64_t); remaining -= sizeof(uint64_t)) {
        uint64_t word;
        std::memcpy(&word, data, sizeof(uint64_t));
        h = mix(h, word);
        data += sizeof(uint64_t);
    }

    if (remaining > 0) {
        uint64_t word = 0;
        std::memcpy(&word, data, remaining);
        h = mix(h, word);
    }

    h ^= h >> 29;
    h *= 0xbf58476d1ce4e5b9ULL;
    return h ^ (h >> 32);
}

} // namespace ddwaf
