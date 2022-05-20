// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.


#pragma once

#include <functional>
#include <set>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <IPWRuleProcessor.h>
#include <PWManifest.h>
#include <utils.h>
#include <validator.hpp>

namespace ddwaf
{

class object_iterator
{
public:
    explicit object_iterator(const ddwaf_object *obj,
        const std::vector<std::string> &path = {},
        const object_limits &limits = object_limits());

    [[nodiscard]] operator bool() const { return current_ != nullptr; }
    [[nodiscard]] bool is_valid() const { return current_ != nullptr; }
    bool operator++();

    // TODO add const, nodiscard, etc
    [[nodiscard]] const ddwaf_object* operator*() const { return current_; }
    [[nodiscard]] DDWAF_OBJ_TYPE type() const { 
        return current_ != nullptr ? current_->type : DDWAF_OBJ_INVALID;
    }

    [[nodiscard]] std::vector<std::string> get_current_path() const;

protected:
    void initialise_cursor(const ddwaf_object *obj);
    void initialise_cursor_with_path(const ddwaf_object *obj,
        const std::vector<std::string> &path);
    void set_cursor_to_next_scalar();

    static constexpr std::size_t initial_stack_size = 32;

    const object_limits limits_;
    std::size_t path_size_{0};
    std::vector<std::pair<const ddwaf_object *, std::size_t>> stack_;
    const ddwaf_object *current_{nullptr};
};

}
