// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <re2/re2.h>
#include <utils.h>
#include <rule_processor/base.hpp>

namespace ddwaf::rule_processor
{

class regex_match: public base
{
public:
    regex_match(const std::string& regex_str, std::size_t minLength, bool caseSensitive);
    ~regex_match() = default;

    std::string_view to_string() const override { return regex->pattern(); }
    std::string_view name() const override { return "match_regex"; }
    std::optional<event::match> match(std::string_view pattern) const override;

protected:
    static constexpr int max_match_count = 16;
    std::unique_ptr<re2::RE2> regex { nullptr };
    std::size_t min_length;
};

}
