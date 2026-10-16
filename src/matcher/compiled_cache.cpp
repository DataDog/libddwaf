// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "ac.h"
#include "matcher/compiled_cache.hpp"
#include "re2.h"

#ifndef _WIN32
#  include <pthread.h>
#endif

namespace ddwaf::matcher {

namespace {

struct compiled_caches {
    compiled_cache<const re2::RE2> regex;
    compiled_cache<ac_t> phrase;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
constinit compiled_caches *caches_instance = nullptr;

// The caches are never destroyed: matchers may be created or destroyed from
// static destructors of other translation units (e.g. a handle owned by a
// global object), so they must outlive every other static.
compiled_caches &caches()
{
    static auto *instance = [] {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        caches_instance = new compiled_caches;
#ifndef _WIN32
        // Rulesets may be built on another thread than the one forking (e.g.
        // a Remote Config update); a child forked while that thread holds the
        // lock of a cache would otherwise never be able to build one.
        pthread_atfork(
            [] {
                caches_instance->regex.lock_for_fork();
                caches_instance->phrase.lock_for_fork();
            },
            [] {
                caches_instance->phrase.unlock_after_fork();
                caches_instance->regex.unlock_after_fork();
            },
            [] {
                caches_instance->phrase.unlock_after_fork();
                caches_instance->regex.unlock_after_fork();
            });
#endif
        return caches_instance;
    }();
    return *instance;
}


// The key is the length-prefixed concatenation of the patterns, which is
// unambiguous and preserves their order (on which the automaton depends).
std::string phrase_key(
    const std::vector<const char *> &patterns, const std::vector<uint32_t> &lengths)
{
    std::size_t size = 0;
    for (auto length : lengths) { size += sizeof(uint32_t) + length; }

    std::string key;
    key.reserve(size);
    for (std::size_t i = 0; i < patterns.size(); ++i) {
        char prefix[sizeof(uint32_t)];
        std::memcpy(prefix, &lengths[i], sizeof(uint32_t));
        key.append(prefix, sizeof(uint32_t));
        key.append(patterns[i], lengths[i]);
    }
    return key;
}

} // namespace

compiled_cache<const re2::RE2> &regex_cache() { return caches().regex; }

compiled_cache<ac_t> &phrase_cache() { return caches().phrase; }

std::shared_ptr<const re2::RE2> compile_regex(std::string_view pattern, bool case_sensitive)
{
    constexpr unsigned regex_max_mem = 512 * 1024;

    std::string key;
    key.reserve(pattern.size() + 1);
    key.push_back(case_sensitive ? 's' : 'i');
    key.append(pattern);

    std::shared_ptr<const re2::RE2> failed;
    auto regex = regex_cache().get_or_compile(std::move(key), [&]() {
        re2::RE2::Options options;
        options.set_max_mem(regex_max_mem);
        options.set_log_errors(false);
        options.set_case_sensitive(case_sensitive);

        auto compiled = std::make_shared<const re2::RE2>(pattern, options);
        if (!compiled->ok()) {
            failed = std::move(compiled);
            return std::shared_ptr<const re2::RE2>{};
        }
        return compiled;
    });

    return regex ? regex : failed;
}

std::shared_ptr<ac_t> compile_phrases(
    const std::vector<const char *> &patterns, const std::vector<uint32_t> &lengths)
{
    return phrase_cache().get_or_compile(phrase_key(patterns, lengths), [&]() {
        // ac_create doesn't modify the patterns, its signature predates const
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        auto **pattern_v = const_cast<const char **>(patterns.data());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        auto *length_v = const_cast<uint32_t *>(lengths.data());
        ac_t *ac = ac_create(pattern_v, length_v, patterns.size());
        if (ac == nullptr) {
            return std::shared_ptr<ac_t>{};
        }
        return std::shared_ptr<ac_t>(ac, ac_free);
    });
}

} // namespace ddwaf::matcher
