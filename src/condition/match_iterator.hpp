// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "clock.hpp"
#include "condition/transforming_iterator.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "object.hpp"
#include "transformer/base.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace ddwaf {

template <std::size_t MinLength = 2, typename IteratorType = kv_iterator,
    typename ResourceType = std::string_view>
class match_iterator {
public:
    static constexpr std::size_t npos = std::string_view::npos;

    explicit match_iterator(ResourceType resource, object_view obj,
        std::span<const transformer_id> transformers, const object_set_ref &exclude,
        ddwaf::timer &deadline)
        : resource_(std::move(resource)), it_(obj, transformers, exclude, deadline)
    {
        find_next_match();
    }

    ~match_iterator() = default;

    match_iterator(const match_iterator &) = delete;
    match_iterator(match_iterator &&) = delete;

    match_iterator &operator=(const match_iterator &) = delete;
    match_iterator &operator=(match_iterator &&) = delete;

    [[nodiscard]] std::pair<std::string_view, std::size_t> operator*()
    {
        return {it_.current_value(), current_index_};
    }

    bool operator++()
    {
        // Look for further occurrences of the current value within the resource
        if (current_index_ != npos) {
            current_index_ = resource_.find(it_.current_value(), current_index_ + 1);
            if (current_index_ != npos) {
                return true;
            }
        }

        ++it_;
        return find_next_match();
    }

    [[nodiscard]] explicit operator bool() const { return static_cast<bool>(it_); }

    [[nodiscard]] std::vector<std::variant<std::string_view, int64_t>> get_current_path() const
    {
        return it_.get_current_path();
    }

protected:
    // Advances the underlying iterator until its current value is found within
    // the resource. Returns false if the iterator was exhausted before finding
    // one. Note that values which don't match are skipped by advancing the
    // underlying iterator, which is also responsible for evaluating the deadline.
    bool find_next_match()
    {
        for (; it_; ++it_) {
            auto value = it_.current_value();
            if (value.size() < MinLength) {
                continue;
            }

            current_index_ = resource_.find(value, 0);
            if (current_index_ != npos) {
                return true;
            }
        }

        return false;
    }

    ResourceType resource_;
    std::size_t current_index_{npos};
    transforming_iterator<IteratorType> it_;
};

} // namespace ddwaf
