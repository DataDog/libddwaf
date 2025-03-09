// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "context_allocator.hpp"
#include "ddwaf.h"
#include "object_view.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

class object_store {
public:
    enum class attribute : uint8_t { none = 0, ephemeral = 1 };

    class eval_scope {
    public:
        explicit eval_scope(object_store &store) : store_(store){};
        eval_scope(const eval_scope &) = delete;
        eval_scope(eval_scope &&) = delete;
        eval_scope &operator=(const eval_scope &) = delete;
        eval_scope &operator=(eval_scope &&) = delete;
        ~eval_scope() { store_.clear_last_batch(); }

    protected:
        object_store &store_;
    };

    object_store() = default;
    ~object_store() = default;
    object_store(const object_store &) = default;
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &) = delete;
    object_store &operator=(object_store &&) = delete;

    bool insert(owned_object &&input, attribute attr = attribute::none);

    // This function doesn't clear the latest batch
    bool insert(target_index target, std::string_view key, owned_object &&input,
        attribute attr = attribute::none);

    std::pair<object_view, attribute> get_target(target_index target) const
    {
        auto it = objects_.find(target);
        if (it != objects_.end()) {
            return {it->second.first, it->second.second};
        }
        return {nullptr, attribute::none};
    }

    bool has_target(target_index target) const { return objects_.find(target) != objects_.end(); }

    bool is_new_target(const target_index target) const
    {
        return latest_batch_.find(target) != latest_batch_.cend();
    }

    bool has_new_targets() const { return !latest_batch_.empty(); }

    bool empty() const { return objects_.empty(); }

    eval_scope get_eval_scope() { return eval_scope{*this}; }

    void clear_last_batch();

protected:
    bool insert_target_helper(target_index target, std::string_view key, object_view view,
        attribute attr = attribute::none);

    memory::list<owned_object> input_objects_;
    memory::list<owned_object> ephemeral_objects_;

    memory::unordered_set<target_index> ephemeral_targets_;

    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, std::pair<object_view, attribute>> objects_;

    friend class scoped_object_store;
};

} // namespace ddwaf
