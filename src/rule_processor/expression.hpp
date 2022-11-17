// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <rule_processor/base.hpp>
#include <string_view>
#include <unordered_map>
#include <utils.h>

#include <bazel-cel-cpp-wrapper/main/cel_wrapper.hpp>

namespace ddwaf::rule_processor {

class expression : public base {
public:
    explicit expression(std::string &expr);

    std::optional<event::match> match(std::string_view str) const override;
    std::string_view name() const override { return "expression"; }

protected:
    static datadog::waf::expression_builder builder;
    std::weak_ptr<datadog::waf::expression> expr_;
};

} // namespace ddwaf::rule_processor
