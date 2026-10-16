// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "cow_string.hpp"
#include "matcher/literal_scanner.hpp"
#include "matcher/regex_prefilter.hpp"
#include "object.hpp"
#include "transformer/base.hpp"

namespace ddwaf::matcher {

// Cache of the literal scans of the strings evaluated during one evaluation,
// so that each (string, transformers) pair is scanned once, however many
// regular expressions are applied to it.
//
// Entries are keyed by the address and size of the string and by the
// transformers applied to it; this is only valid while the evaluated objects
// can't be modified or freed, i.e. for the duration of one evaluation (see
// prefilter_scope). Transformed strings are not used as keys, as they are
// temporary.
//
// There is one cache per thread, reused by every evaluation on that thread.
class prefilter_cache {
public:
    prefilter_cache() = default;
    prefilter_cache(const prefilter_cache &) = delete;
    prefilter_cache(prefilter_cache &&) = delete;
    prefilter_cache &operator=(const prefilter_cache &) = delete;
    prefilter_cache &operator=(prefilter_cache &&) = delete;
    ~prefilter_cache() = default;

    // The cache of the evaluation in progress on this thread, or nullptr.
    static prefilter_cache *current();

    // Whether this evaluation's scanner can be used to evaluate the prefilter.
    [[nodiscard]] bool supports(const regex_prefilter &prefilter) const;

    // Returns false if the prefilter proves that its regular expression can't
    // match the string `src` transformed by `transformers`. If the
    // transformation had to be performed to find out, its result is stored in
    // `transformed` and `transformed_valid` is set, so that the caller doesn't
    // need to perform it again.
    bool may_match(const regex_prefilter &prefilter, object_view src,
        std::span<const transformer_id> transformers, std::optional<cow_string> &transformed,
        bool &transformed_valid);

protected:
    struct scan_result {
        uint64_t mask{0};
        // The atoms found are found_[offset, offset + count)
        uint32_t offset{0};
        uint32_t count : 31 {0};
        bool unfiltered : 1 {false};
    };

    struct slot {
        const char *data{nullptr};
        uint64_t chain{0};
        uint32_t size{0};
        uint32_t generation{0};
        scan_result result;
    };

    void reset(const literal_scanner *scanner);
    scan_result scan(std::string_view str);
    // The string must be smaller than 4GiB
    const scan_result *find(std::string_view str, uint64_t chain) const;
    // Returns false if the cache is full, in which case the result isn't cached
    bool insert(std::string_view str, uint64_t chain, const scan_result &result);
    void grow();
    [[nodiscard]] bool evaluate(const regex_prefilter &prefilter, const scan_result &result) const;
    // Evaluates the result of the last scan, whose atoms are discarded unless
    // the result has been retained by the cache
    bool evaluate_scan(const regex_prefilter &prefilter, const scan_result &result, bool retained);

    static std::size_t hash_key(std::string_view str, uint64_t chain);

    const literal_scanner *scanner_{nullptr};
    literal_scanner::scratch scratch_;
    // Concatenated sorted atom hashes of every scan
    std::vector<uint64_t> found_;
    std::vector<slot> slots_;
    std::size_t used_{0};
    uint32_t generation_{0};
    // Consecutive evaluations which used a small part of the memory
    unsigned small_evaluations_{0};

    friend class prefilter_scope;
};

// Enables prefiltering on this thread for its lifetime, with the scanner of
// the ruleset being evaluated, and invalidates the cache of the previous
// evaluation.
class prefilter_scope {
public:
    explicit prefilter_scope(const literal_scanner *scanner);
    prefilter_scope(const prefilter_scope &) = delete;
    prefilter_scope(prefilter_scope &&) = delete;
    prefilter_scope &operator=(const prefilter_scope &) = delete;
    prefilter_scope &operator=(prefilter_scope &&) = delete;
    ~prefilter_scope();

protected:
    prefilter_cache *previous_;
};

} // namespace ddwaf::matcher
