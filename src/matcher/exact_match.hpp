// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dynamic_string.hpp"
#include "expiring_string_list.hpp"
#include "indexed_multivector.hpp"
#include "matcher/base.hpp"
#include "object_type.hpp"

namespace ddwaf::matcher {

class exact_match : public base_impl<exact_match> {
public:
    using data_type = std::vector<std::pair<std::string, uint64_t>>;

    static constexpr std::string_view matcher_name = "exact_match";
    static constexpr std::string_view negated_matcher_name = "!exact_match";

    exact_match() = default;
    explicit exact_match(std::vector<std::string> &&data);
    explicit exact_match(
        const indexed_multivector<std::string, std::pair<std::string, uint64_t>> &data);
    explicit exact_match(const indexed_multivector<std::string, expiring_string_list::value_type,
        expiring_string_list> &data);
    explicit exact_match(const data_type &data);
    ~exact_match() override = default;
    exact_match(const exact_match &) = default;
    exact_match(exact_match &&) = default;
    exact_match &operator=(const exact_match &) = default;
    exact_match &operator=(exact_match &&) = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(object_type type)
    {
        return (type & object_type::string) != 0;
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(std::string_view str) const;

    template <typename T> void build(const T &data);
    [[nodiscard]] const uint64_t *find(std::string_view str) const;

    // The distinct values are stored back to back in buffer_ and indexed by
    // an open-addressing hash table, so that building, copying and destroying
    // the matcher doesn't require one allocation per value.
    struct entry {
        std::size_t offset;
        std::size_t length;
        uint64_t expiration;
    };

    std::string buffer_;
    std::vector<entry> entries_;
    // Linear-probing table of 1-based indexes into entries_ (0 marks an empty
    // slot); the upper 32 bits hold the upper bits of the hash of the value.
    std::vector<uint64_t> slots_;
    std::size_t max_length_{0};

    friend class base_impl<exact_match>;
};

} // namespace ddwaf::matcher
