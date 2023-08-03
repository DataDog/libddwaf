// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ac.h>
#include <memory>
#include <operation/base.hpp>

namespace ddwaf::operation {

class phrase_match : public base_impl<phrase_match> {
public:
    phrase_match(std::vector<const char *> pattern, std::vector<uint32_t> lengths);
    ~phrase_match() override = default;
    phrase_match(const phrase_match &) = delete;
    phrase_match(phrase_match &&) noexcept = default;
    phrase_match &operator=(const phrase_match &) = delete;
    phrase_match &operator=(phrase_match &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "phrase_match"; }
    static constexpr DDWAF_OBJ_TYPE supported_type_impl() { return DDWAF_OBJ_STRING; }

    [[nodiscard]] std::pair<bool, memory::string> match_impl(std::string_view pattern) const;

    std::unique_ptr<ac_t, void (*)(void *)> ac{nullptr, nullptr};

    friend class base_impl<phrase_match>;
};

} // namespace ddwaf::operation
