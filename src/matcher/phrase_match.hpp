// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ac.h>
#include <memory>
#include <vector>

#include "matcher/base.hpp"

namespace ddwaf::matcher {

class phrase_match : public base_impl<phrase_match> {
public:
    phrase_match(std::vector<const char *> pattern, std::vector<uint32_t> lengths,
        bool enforce_word_boundary = false);
    ~phrase_match() override = default;
    phrase_match(const phrase_match &) = delete;
    phrase_match(phrase_match &&) noexcept = default;
    phrase_match &operator=(const phrase_match &) = delete;
    phrase_match &operator=(phrase_match &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "phrase_match"; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view pattern) const;

    bool enforce_word_boundary_{false};
    std::unique_ptr<ac_t, void (*)(void *)> ac{nullptr, nullptr};

    friend class base_impl<phrase_match>;
};

} // namespace ddwaf::matcher
