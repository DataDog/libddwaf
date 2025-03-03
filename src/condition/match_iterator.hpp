// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "iterator.hpp"
#include "object_view.hpp"

namespace ddwaf {

template <std::size_t MinLength = 2, typename IteratorType = kv_iterator,
    typename ResourceType = std::string_view>
class match_iterator {
public:
    static constexpr std::size_t npos = std::string_view::npos;

    explicit match_iterator(ResourceType resource, object_view obj,
        const exclusion::object_set_ref &exclude, const object_limits &limits = {})
        : resource_(resource), it_(obj, {}, exclude, limits)
    {
        for (; it_; ++it_) {
            auto current_obj = *it_;
            if (current_obj.type() == object_type::string && current_obj->size() >= MinLength) {
                current_param_ = current_obj->template as<
                    std::string_view>(); //{
                                         // current_obj->stringValue,
                                         // static_cast<std::size_t>(current_obj->nbEntries)};
                current_index_ = resource_.find(current_param_, 0);
                if (current_index_ != npos) {
                    break;
                }
            }
        }
    }

    ~match_iterator() = default;

    match_iterator(const match_iterator &) = default;
    match_iterator(match_iterator &&) = delete;

    match_iterator &operator=(const match_iterator &) = delete;
    match_iterator &operator=(match_iterator &&) = delete;

    [[nodiscard]] std::pair<std::string_view, std::size_t> operator*()
    {
        return {current_param_, current_index_};
    }

    bool operator++()
    {
        if (current_index_ != npos) {
            current_index_ = resource_.find(current_param_, current_index_ + 1);
            if (current_index_ != npos) {
                return true;
            }
        }

        while (++it_) {
            auto current_obj = *it_;
            if (current_obj.type() == object_type::string && current_obj->size() >= MinLength) {
                current_param_ = current_obj->template as<std::string_view>();
                current_index_ = resource_.find(current_param_, 0);
                if (current_index_ != npos) {
                    return true;
                }
            }
        }

        return false;
    }

    [[nodiscard]] explicit operator bool() const { return static_cast<bool>(it_); }

    [[nodiscard]] std::vector<std::string> get_current_path() const
    {
        return it_.get_current_path();
    }

protected:
    ResourceType resource_;
    std::string_view current_param_;
    std::size_t current_index_{npos};
    IteratorType it_;
};

} // namespace ddwaf
