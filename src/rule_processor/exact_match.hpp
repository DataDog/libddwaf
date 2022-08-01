// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <rule_processor/base.hpp>
#include <clock.hpp>
#include <string_view>
#include <utils.h>
#include <unordered_set>

namespace ddwaf::rule_processor
{

class exact_match : public rule_processor_base
{
public:
    explicit exact_match(std::vector<std::string> &&data);
    ~exact_match() = default;
    bool match(const char* str, size_t length, MatchGatherer& gatherer) const override;
    std::string_view name() const override { return "exact_match"; }
protected:
    std::vector<std::string> data_;
    std::unordered_set<std::string_view> values_;
};

}
