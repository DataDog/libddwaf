// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <rule_processor/base.hpp>
#include <libinjection.h>

namespace ddwaf::rule_processor
{

class is_sqli : public rule_processor_base
{
public:
    is_sqli() = default;
    std::string_view name() const override { return "is_sqli"; }
    bool match(const char* pattern, size_t length, MatchGatherer& gatherer) const override;
};

class is_xss : public rule_processor_base
{
public:
    is_xss() = default;
    std::string_view name() const override { return "is_xss"; }

    bool match(const char* pattern, size_t length, MatchGatherer& gatherer) const override;
};

}
