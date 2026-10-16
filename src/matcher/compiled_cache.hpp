// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ac.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <re2/re2.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ddwaf::matcher {

// Compiling regular expressions and Aho-Corasick automata dominates the cost of
// building a ruleset. The same pattern often appears several times in one
// ruleset (for example, one regex shared by many scanners), and when a Remote
// Config update replaces a rules configuration, most of its patterns are the
// ones already compiled for the instance in use. Compiled RE2 programs and
// Aho-Corasick automata are immutable and safe to use from several threads, so
// a single compiled object can back every matcher with the same source.
//
// The cache is process-wide and holds only weak references: a compiled object
// is reused while some matcher (owned by a builder, or by an instance still in
// use) refers to it, and is freed with its last user, so the cache never keeps
// compiled objects alive by itself. Expired entries are swept when the table
// has doubled since the previous sweep.
template <typename T> class compiled_cache {
public:
    compiled_cache() = default;
    ~compiled_cache() = default;
    compiled_cache(const compiled_cache &) = delete;
    compiled_cache(compiled_cache &&) = delete;
    compiled_cache &operator=(const compiled_cache &) = delete;
    compiled_cache &operator=(compiled_cache &&) = delete;

    // Returns the live object compiled from the given key or, if there is
    // none, the result of compile(). A null result (a compilation failure) is
    // returned as is and not cached.
    template <typename Compile>
    std::shared_ptr<T> get_or_compile(std::string key, Compile &&compile)
    {
        {
            const std::lock_guard lock{mtx_};
            auto it = entries_.find(key);
            if (it != entries_.end()) {
                if (auto obj = it->second.lock(); obj) {
                    return obj;
                }
            }
        }

        // Compile without holding the lock, so that builds on other threads
        // aren't serialised behind this one.
        std::shared_ptr<T> obj = std::forward<Compile>(compile)();
        if (!obj) {
            return obj;
        }

        const std::lock_guard lock{mtx_};
        auto [it, inserted] = entries_.try_emplace(std::move(key), obj);
        if (!inserted) {
            // Another thread may have compiled the same key concurrently
            if (auto existing = it->second.lock(); existing) {
                return existing;
            }
            it->second = obj;
        } else if (entries_.size() > sweep_threshold_) {
            sweep();
        }
        return obj;
    }

    [[nodiscard]] std::size_t size() const
    {
        const std::lock_guard lock{mtx_};
        return entries_.size();
    }

    // See compiled_cache.cpp
    void lock_for_fork() { mtx_.lock(); }
    void unlock_after_fork() { mtx_.unlock(); }

protected:
    static constexpr std::size_t min_sweep_threshold = 64;

    void sweep()
    {
        std::erase_if(entries_, [](const auto &entry) { return entry.second.expired(); });
        sweep_threshold_ = std::max(min_sweep_threshold, entries_.size() * 2);
    }

    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::weak_ptr<T>> entries_;
    std::size_t sweep_threshold_{min_sweep_threshold};
};

// The process-wide caches used by compile_regex and compile_phrases, exposed
// for testing.
compiled_cache<const re2::RE2> &regex_cache();
compiled_cache<ac_t> &phrase_cache();

// Compiles a regular expression with the options used by all regex-based
// matchers, sharing the program with other live matchers using the same
// pattern and case sensitivity. The caller must check ok() on the result:
// regexes which fail to compile are not shared.
std::shared_ptr<const re2::RE2> compile_regex(std::string_view pattern, bool case_sensitive);

// Builds an Aho-Corasick automaton over the given patterns, sharing it with
// other live matchers using the same patterns in the same order. Returns null
// if the automaton can't be created.
std::shared_ptr<ac_t> compile_phrases(
    const std::vector<const char *> &patterns, const std::vector<uint32_t> &lengths);

} // namespace ddwaf::matcher
