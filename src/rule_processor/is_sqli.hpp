// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <libinjection.h>
#include <rule_processor/base.hpp>

namespace ddwaf::rule_processor {

class is_sqli : public base {
public:
    is_sqli() = default;
    [[nodiscard]] std::string_view name() const override { return "is_sqli"; }
    [[nodiscard]] std::optional<event::match> do_match(
        std::string_view pattern, allocator alloc) const override;

protected:
    static constexpr unsigned fingerprint_length = 16;
};

} // namespace ddwaf::rule_processor
