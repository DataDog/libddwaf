// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <boost/unordered/unordered_flat_map.hpp>
#include <string>
#include <string_view>

#include "log.hpp"
#include "matcher/base.hpp"

namespace ddwaf {
class scanner {
public:
    scanner(std::string id, boost::unordered_flat_map<std::string, std::string> tags,
        std::unique_ptr<matcher::base> key_matcher, std::unique_ptr<matcher::base> value_matcher)
        : id_(std::move(id)), tags_(std::move(tags)), key_matcher_(std::move(key_matcher)),
          value_matcher_(std::move(value_matcher))
    {}

    scanner(const scanner &) = default;
    scanner &operator=(const scanner &) = default;

    scanner(scanner &&) = default;
    scanner &operator=(scanner &&) = default;

    virtual ~scanner() = default;

    bool eval(std::string_view key, object_view value) const
    {
        DDWAF_DEBUG("Evaluating scanner '{}'", id_);
        return eval_matcher(key_matcher_, key) && eval_matcher(value_matcher_, value);
    }

    const boost::unordered_flat_map<std::string, std::string> &get_tags() const { return tags_; }
    std::string_view get_id() const { return id_; }
    const std::string &get_id_ref() const { return id_; }

protected:
    static bool eval_matcher(const std::shared_ptr<matcher::base> &matcher, object_view data)
    {
        if (!matcher) {
            return true;
        }
        if (!data.has_value() || data.type() == object_type::invalid) {
            return false;
        }
        return matcher->match(data).first;
    }

    static bool eval_matcher(const std::shared_ptr<matcher::base> &matcher, std::string_view data)
    {
        if (!matcher) {
            return true;
        }
        if (data.empty()) {
            return false;
        }
        return matcher->match(data).first;
    }

    std::string id_;
    boost::unordered_flat_map<std::string, std::string> tags_;
    std::shared_ptr<matcher::base> key_matcher_;
    std::shared_ptr<matcher::base> value_matcher_;
};

} // namespace ddwaf
