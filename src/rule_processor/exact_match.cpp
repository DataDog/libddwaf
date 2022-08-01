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

std::optional<event::match> exact_match::match(std::string_view str) const
{
    if (str.empty() || str.data() == nullptr) {
        return {};
    }

    auto it = values_.find(str);
    if (it == values_.end()) {
        return {};
    }

    return make_event(str, str);
}

}
