// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <rule_processor/exact_match.hpp>

namespace ddwaf::rule_processor
{

bool exact_match::match(const char* str, size_t length, MatchGatherer& gatherer) const
{
    std::string value{str, length};

    auto it = data_.find(value);
    if (it == data_.end()) {
        return false;
    }

    gatherer.resolvedValue = value;
    gatherer.matchedValue = value;

    return true;
}

}
