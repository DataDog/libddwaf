// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <rule_processor/exact_match.hpp>

namespace ddwaf::rule_processor {

exact_match::exact_match(std::vector<std::string> &&data) : data_(std::move(data))
{
    values_.reserve(data_.size());
    for (const auto &str : data_) { values_.emplace(str, 0); }
}

exact_match::exact_match(const std::vector<std::pair<std::string_view, uint64_t>> &data)
{
    data_.reserve(data.size());
    values_.reserve(data.size());
    for (auto [str, expiration] : data) {
        const auto &ref = data_.emplace_back(str);
        auto res = values_.emplace(ref, expiration);
        if (!res.second) {
            uint64_t prev_expiration = res.first->second;
            if (prev_expiration != 0 && (expiration == 0 || expiration > prev_expiration)) {
                res.first->second = expiration;
            }
        }
    }
}

std::optional<event::match> exact_match::match(std::string_view str) const
{
    if (values_.empty() || str.empty() || str.data() == nullptr) {
        return std::nullopt;
    }

    auto it = values_.find(str);
    if (it == values_.end()) {
        return std::nullopt;
    }

    if (it->second > 0) {
        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
                           .count();
        if (it->second < now) {
            return std::nullopt;
        }
    }
    return make_event(str, str);
}

} // namespace ddwaf::rule_processor
