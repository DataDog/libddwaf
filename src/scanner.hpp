// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

#include "log.hpp"
#include "matcher/base.hpp"

namespace ddwaf {
class scanner {
public:
    scanner(std::string id, std::unordered_map<std::string, std::string> tags,
        std::unique_ptr<matcher::base> key_matcher, std::unique_ptr<matcher::base> value_matcher)
        : id_(std::move(id)), tags_(std::move(tags)), key_matcher_(std::move(key_matcher)),
          value_matcher_(std::move(value_matcher))
    {}

    scanner(const scanner &) = delete;
    scanner &operator=(const scanner &) = delete;

    scanner(scanner &&) = default;
    scanner &operator=(scanner &&) = default;

    virtual ~scanner() = default;

    bool eval(const ddwaf_object &key, const ddwaf_object &value) const
    {
        DDWAF_DEBUG("Evaluating scanner '{}'", id_);
        return eval_matcher(key_matcher_, key) && eval_matcher(value_matcher_, value);
    }

    bool eval(std::string_view key, const ddwaf_object &value) const
    {
        ddwaf_object key_obj;
        if (key.data() != nullptr && !key.empty()) {
            ddwaf_object_stringl_nc(&key_obj, key.data(), key.size());
        } else {
            ddwaf_object_invalid(&key_obj);
        }
        return eval(key_obj, value);
    }

    const std::unordered_map<std::string, std::string> &get_tags() const { return tags_; }
    std::string_view get_id() const { return id_; }
    const std::string &get_id_ref() const { return id_; }

protected:
    static bool eval_matcher(const std::unique_ptr<matcher::base> &matcher, const ddwaf_object &obj)
    {
        if (!matcher) {
            return true;
        }
        if (obj.type == DDWAF_OBJ_INVALID) {
            return false;
        }
        return matcher->match(obj).first;
    }

    std::string id_;
    std::unordered_map<std::string, std::string> tags_;
    std::unique_ptr<matcher::base> key_matcher_;
    std::unique_ptr<matcher::base> value_matcher_;
};

} // namespace ddwaf
