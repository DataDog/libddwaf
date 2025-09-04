// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "context_allocator.hpp"
#include "object.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

class object_store {
public:
    object_store() = default;
    ~object_store() = default;
    object_store(const object_store &) = default;
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &) = delete;
    object_store &operator=(object_store &&) = delete;

    bool insert(owned_object &&input, evaluation_scope scope = evaluation_scope::context());

    // This function doesn't clear the latest batch
    bool insert(target_index target, std::string_view key, owned_object &&input,
        evaluation_scope scope = evaluation_scope::context());

    // Used for testing
    bool insert(map_view input, evaluation_scope scope = evaluation_scope::context());

    std::pair<object_view, evaluation_scope> get_target(target_index target) const
    {
        auto it = objects_.find(target);
        if (it != objects_.end()) {
            return {it->second.first, it->second.second};
        }
        return {nullptr, evaluation_scope::context()};
    }

    // Used for testing
    std::pair<object_view, evaluation_scope> get_target(std::string_view name) const
    {
        return get_target(get_target_index(name));
    }

    bool has_target(target_index target) const { return objects_.contains(target); }

    bool is_new_target(const target_index target) const { return latest_batch_.contains(target); }

    bool has_new_targets() const { return !latest_batch_.empty(); }

    bool empty() const { return objects_.empty(); }

    void clear_last_batch() { latest_batch_.clear(); }

    void clear_subcontext_objects()
    {
        // Clear any subcontext targets
        for (auto target : subcontext_targets_) {
            auto it = objects_.find(target);
            if (it != objects_.end()) {
                objects_.erase(it);
            }
        }
        subcontext_targets_.clear();

        // Free subcontext objects and targets
        subcontext_objects_.clear();
    }

protected:
    bool insert_target_helper(target_index target, std::string_view key, object_view view,
        evaluation_scope scope = evaluation_scope::context());

    memory::list<owned_object> input_objects_;
    std::list<owned_object> subcontext_objects_;

    std::unordered_set<target_index> subcontext_targets_;

    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, std::pair<object_view, evaluation_scope>> objects_;

    friend class scoped_object_store;
};

} // namespace ddwaf
