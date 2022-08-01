// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <rule_processor/exact_match.hpp>

namespace ddwaf::rule_processor
{

exact_match::exact_match(std::vector<std::string> &&data):
    data_(std::move(data))
{
    values_.reserve(data_.size());
    values_.insert(data_.cbegin(), data_.cend());
}

bool exact_match::match(const char* str, size_t length, MatchGatherer& gatherer) const
{
    if (str == nullptr || length == 0) {
        return false;
    }

    auto it = values_.find({str, length});
    if (it == values_.end()) {
        return false;
    }

    gatherer.resolvedValue = *it;
    gatherer.matchedValue = *it;

    return true;
}

}
