// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>

#include <matcher/base.hpp>

namespace ddwaf {
class scanner {
public:
    using ptr = std::shared_ptr<scanner>;

    scanner(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        matcher::base::unique_ptr key_matcher, matcher::base::unique_ptr value_matcher)
        : id_(std::move(id)), name_(std::move(name)), tags_(std::move(tags)),
          key_matcher_(std::move(key_matcher)), value_matcher_(std::move(value_matcher))
    {}

    scanner(const scanner &) = delete;
    scanner &operator=(const scanner &) = delete;

    scanner(scanner &&) = default;
    scanner &operator=(scanner &&) = default;

    virtual ~scanner() = default;

    bool eval(const ddwaf_object &key, const ddwaf_object &value) const
    {
        return eval_matcher(key_matcher_, key) && eval_matcher(value_matcher_, value);
    }

    constexpr const std::unordered_map<std::string, std::string> &get_tags() const { return tags_; }
    constexpr std::string_view get_id() const { return id_; }
    constexpr std::string_view get_name() const { return name_; }

protected:
    static bool eval_matcher(const matcher::base::unique_ptr &matcher, const ddwaf_object &obj)
    {
        return matcher ? matcher->match(obj).first : true;
    }

    std::string id_;
    std::string name_;
    std::unordered_map<std::string, std::string> tags_;
    matcher::base::unique_ptr key_matcher_;
    matcher::base::unique_ptr value_matcher_;
};

} // namespace ddwaf
