// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <libinjection.h>
#include <rule_processor/base.hpp>

namespace ddwaf::rule_processor {

class is_xss : public base {
public:
    is_xss() = default;
    [[nodiscard]] std::string_view name() const override { return "is_xss"; }
    [[nodiscard]] std::optional<event::match> do_match(
        std::string_view pattern, allocator alloc) const override;
};

} // namespace ddwaf::rule_processor
