// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <expression.hpp>

namespace ddwaf::rule_processor {

// NOLINTNEXTLINE
datadog::waf::expression_builder expression::builder{};

expression::expression(std::string &expr):
    expr_(expression::builder.build(expr)) {}


std::optional<event::match> expression::match(std::string_view str) const
{
    return std::nullopt;
}


}
