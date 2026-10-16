// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "cow_string.hpp"
#include "matcher/literal_scanner.hpp"
#include "matcher/prefilter_cache.hpp"
#include "matcher/regex_prefilter.hpp"
#include "object.hpp"
#include "thread_exit.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"

namespace ddwaf::matcher {

namespace {

constexpr std::size_t initial_capacity = 256;
constexpr std::size_t large_capacity = 4096;
constexpr unsigned max_small_evaluations = 1024;
// Past this many entries, scans are no longer cached
constexpr std::size_t max_entries = std::size_t{1} << 14;

thread_local constinit prefilter_cache *current_cache = nullptr;

enum class cache_state : uint8_t { unused, active, destroyed };

// The cache of the thread, allocated on its first evaluation and freed when
// the thread exits (see thread_exit::register_callback). A static thread_local
// cache would be destroyed before the static objects and, on glibc, before the
// thread_local objects constructed before it, any of which may still evaluate
// from its destructor; and it would keep libddwaf.so from being unloaded.
thread_local constinit prefilter_cache *thread_cache_ptr = nullptr;
thread_local constinit cache_state thread_cache_state = cache_state::unused;

void reap_thread_cache() noexcept
{
    delete thread_cache_ptr;
    thread_cache_ptr = nullptr;
    thread_cache_state = cache_state::destroyed;
}

// Returns null once the cache of the thread has been freed, or if it can't be
// freed when the thread exits
prefilter_cache *thread_cache()
{
    if (thread_cache_state == cache_state::active) [[likely]] {
        return thread_cache_ptr;
    }

    if (thread_cache_state == cache_state::destroyed ||
        !thread_exit::register_callback(reap_thread_cache)) {
        thread_cache_state = cache_state::destroyed;
        return nullptr;
    }

    thread_cache_ptr = new prefilter_cache();
    thread_cache_state = cache_state::active;
    return thread_cache_ptr;
}

// Encodes a sequence of transformers as a non-zero integer (zero stands for
// no transformers), or returns nullopt if the sequence is too long.
std::optional<uint64_t> encode_transformers(std::span<const transformer_id> transformers)
{
    constexpr unsigned bits_per_transformer = 5;
    static_assert(static_cast<unsigned>(transformer_id::unicode_normalize) + 1 <
                  (1U << bits_per_transformer));

    if (transformers.size() > 64 / bits_per_transformer) {
        return std::nullopt;
    }

    uint64_t key = 0;
    for (auto id : transformers) {
        key = (key << bits_per_transformer) | (static_cast<uint64_t>(id) + 1);
    }
    return key;
}

} // namespace

prefilter_cache *prefilter_cache::current() { return current_cache; }

bool prefilter_cache::supports(const regex_prefilter &prefilter) const
{
    const auto id = scanner_->id();
    const auto hint = prefilter.coverage_hint();
    if (hint == id) {
        return true;
    }
    if (hint == (id | 1)) {
        return false;
    }

    const bool covered = scanner_->covers(prefilter);
    prefilter.set_coverage_hint(covered ? id : (id | 1));
    return covered;
}

bool prefilter_cache::may_match(const regex_prefilter &prefilter, object_view src,
    std::span<const transformer_id> transformers, std::optional<cow_string> &transformed,
    bool &transformed_valid)
{
    // Atoms are searched for case-insensitively, so a final lowercase
    // transformation can't change which ones are present
    auto effective = transformers;
    while (!effective.empty() && effective.back() == transformer_id::lowercase) {
        effective = effective.first(effective.size() - 1);
    }

    const auto str = src.as<std::string_view>();
    // Strings of 4GiB or more are never cached
    const bool cacheable = str.size() <= std::numeric_limits<uint32_t>::max();
    if (effective.empty()) {
        const auto *cached = cacheable ? find(str, 0) : nullptr;
        if (cached != nullptr) {
            return evaluate(prefilter, *cached);
        }
        auto result = scan(str);
        const bool retained = cacheable && insert(str, 0, result);
        return evaluate_scan(prefilter, result, retained);
    }

    auto chain = cacheable ? encode_transformers(effective) : std::nullopt;
    if (chain.has_value()) {
        const auto *cached = find(str, *chain);
        if (cached != nullptr) {
            return evaluate(prefilter, *cached);
        }
    }

    auto result_transformed = transformer::manager::transform(src, effective);
    scan_result result;
    // Whether the atoms found by the scan are referred to by a cache entry
    bool retained = false;
    if (result_transformed.has_value()) {
        result = scan(static_cast<std::string_view>(*result_transformed));
    } else {
        // The transformers left the string unchanged
        const auto *cached = cacheable ? find(str, 0) : nullptr;
        if (cached != nullptr) {
            result = *cached;
            retained = true;
        } else {
            result = scan(str);
            retained = cacheable && insert(str, 0, result);
        }
    }

    if (chain.has_value()) {
        retained = insert(str, *chain, result) || retained;
    }

    if (effective.size() == transformers.size()) {
        transformed = std::move(result_transformed);
        transformed_valid = true;
    }

    return evaluate_scan(prefilter, result, retained);
}

bool prefilter_cache::evaluate_scan(
    const regex_prefilter &prefilter, const scan_result &result, bool retained)
{
    const bool may_match = evaluate(prefilter, result);
    if (!retained) {
        // The result of the scan, the last one, isn't cached (the cache is
        // full), so its atoms are dropped rather than accumulated for every
        // regular expression applied to an uncached string.
        found_.resize(result.offset);
    }
    return may_match;
}

void prefilter_cache::reset(const literal_scanner *scanner)
{
    scanner_ = scanner;

    // The memory used by an unusually large evaluation is only released once
    // many smaller ones have followed, as evaluations of different sizes
    // alternate within a request
    const bool large = slots_.size() > large_capacity || found_.capacity() > large_capacity;
    if (large && used_ * 8 < slots_.size() && found_.size() * 8 < found_.capacity()) {
        if (++small_evaluations_ >= max_small_evaluations) {
            slots_ = {};
            found_ = {};
            small_evaluations_ = 0;
        }
    } else {
        small_evaluations_ = 0;
    }

    found_.clear();
    used_ = 0;
    if (++generation_ == 0) {
        std::fill(slots_.begin(), slots_.end(), slot{});
        generation_ = 1;
    }
}

prefilter_cache::scan_result prefilter_cache::scan(std::string_view str)
{
    scan_result result;
    result.offset = static_cast<uint32_t>(found_.size());
    auto res = scanner_->scan(str, scratch_, found_);
    result.count = static_cast<uint32_t>(found_.size() - result.offset);
    result.mask = res.mask;
    result.unfiltered = res.unfiltered;
    return result;
}

bool prefilter_cache::evaluate(const regex_prefilter &prefilter, const scan_result &result) const
{
    if (result.unfiltered) {
        return true;
    }

    if ((result.mask & prefilter.atom_mask()) == 0) {
        return false;
    }

    return prefilter.may_match(
        std::span<const uint64_t>{found_}.subspan(result.offset, result.count));
}

std::size_t prefilter_cache::hash_key(std::string_view str, uint64_t chain)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto key = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(str.data()));
    key ^= (static_cast<uint64_t>(str.size()) * 0x9E3779B97F4A7C15ULL) ^
           (chain * 0xC2B2AE3D27D4EB4FULL);
    key ^= key >> 29;
    key *= 0xBF58476D1CE4E5B9ULL;
    key ^= key >> 32;
    return static_cast<std::size_t>(key);
}

const prefilter_cache::scan_result *prefilter_cache::find(
    std::string_view str, uint64_t chain) const
{
    if (used_ == 0) {
        return nullptr;
    }

    const auto size = static_cast<uint32_t>(str.size());
    const std::size_t mask = slots_.size() - 1;
    for (std::size_t i = hash_key(str, chain) & mask;; i = (i + 1) & mask) {
        const auto &s = slots_[i];
        if (s.generation != generation_) {
            return nullptr;
        }
        if (s.data == str.data() && s.size == size && s.chain == chain) {
            return &s.result;
        }
    }
}

bool prefilter_cache::insert(std::string_view str, uint64_t chain, const scan_result &result)
{
    if (used_ >= max_entries) {
        return false;
    }

    if ((used_ + 1) * 2 > slots_.size()) {
        grow();
    }

    const std::size_t mask = slots_.size() - 1;
    for (std::size_t i = hash_key(str, chain) & mask;; i = (i + 1) & mask) {
        auto &s = slots_[i];
        if (s.generation != generation_) {
            s = {.data = str.data(),
                .chain = chain,
                .size = static_cast<uint32_t>(str.size()),
                .generation = generation_,
                .result = result};
            ++used_;
            return true;
        }
    }
}

void prefilter_cache::grow()
{
    const std::vector<slot> old = std::move(slots_);
    slots_.assign(old.empty() ? initial_capacity : old.size() * 2, slot{});

    const std::size_t mask = slots_.size() - 1;
    for (const auto &s : old) {
        if (s.generation != generation_) {
            continue;
        }
        for (std::size_t i = hash_key(std::string_view{s.data, s.size}, s.chain) & mask;;
             i = (i + 1) & mask) {
            if (slots_[i].generation != generation_) {
                slots_[i] = s;
                break;
            }
        }
    }
}

prefilter_scope::prefilter_scope(const literal_scanner *scanner) : previous_(current_cache)
{
    // A nested evaluation would invalidate the cache of the enclosing one, so
    // prefiltering is disabled instead (this isn't expected to happen).
    // Without a cache, e.g. on a thread which is exiting, it's disabled too.
    auto *cache = scanner != nullptr && previous_ == nullptr ? thread_cache() : nullptr;
    if (cache == nullptr) {
        current_cache = nullptr;
        return;
    }

    cache->reset(scanner);
    current_cache = cache;
}

prefilter_scope::~prefilter_scope() { current_cache = previous_; }

} // namespace ddwaf::matcher
