// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "log.hpp"
#include "object.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

class object_store {
public:
    ~object_store() = default;
    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    object_store(const object_store &) = delete;
    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &) = delete;
    object_store &operator=(object_store &&) = default;

    bool insert(owned_object &&input)
    {
        object_view view = input_objects_.emplace_back(std::move(input));
        if (!view.is_map()) {
            return false;
        }

        return insert(view);
    }

    bool insert(map_view input)
    {
        const auto size = input.size();
        if (size == 0) {
            // Objects with no addresses are considered valid as they are harmless
            return true;
        }

        objects_.reserve(objects_.size() + size);
        latest_batch_.reserve(latest_batch_.size() + size);

        for (std::size_t i = 0; i < size; ++i) {
            auto [key_obj, value] = input.at(i);
            if (key_obj.empty()) {
                continue;
            }

            auto key = key_obj.as<std::string_view>();
            auto target = get_target_index(key);
            insert_target_helper(target, key, value, scope_);
        }

        return true;
    }

    bool insert(target_index target, std::string_view key, owned_object &&input)
    {
        object_view view = input_objects_.emplace_back(std::move(input));

        return insert_target_helper(target, key, view, scope_);
    }

    [[nodiscard]] std::pair<object_view, evaluation_scope> get_target(target_index target) const
    {
        auto it = objects_.find(target);
        if (it != objects_.end()) {
            return {it->second.first, it->second.second};
        }
        return {nullptr, evaluation_scope::context()};
    }

    // Used for testing
    [[nodiscard]] std::pair<object_view, evaluation_scope> get_target(std::string_view name) const
    {
        return get_target(get_target_index(name));
    }

    [[nodiscard]] bool has_target(target_index target) const { return objects_.contains(target); }
    [[nodiscard]] bool is_new_target(const target_index target) const
    {
        return latest_batch_.contains(target);
    }
    [[nodiscard]] bool has_new_targets() const { return !latest_batch_.empty(); }
    [[nodiscard]] bool empty() const { return objects_.empty(); }
    void clear_last_batch() { latest_batch_.clear(); }

    static object_store make_context_store() { return object_store{evaluation_scope::context()}; }
    static object_store make_subcontext_store(const object_store &upstream)
    {
        auto store = object_store{evaluation_scope::subcontext()};
        store.latest_batch_ = upstream.latest_batch_;
        store.objects_ = upstream.objects_;
        return store;
    }
    // For testing purposes
    static object_store make_subcontext_store()
    {
        return object_store{evaluation_scope::subcontext()};
    }

private:
    explicit object_store(evaluation_scope scope) : scope_(scope) {}

    bool insert_target_helper(
        target_index target, std::string_view key, object_view view, evaluation_scope scope)
    {
        if (objects_.contains(target)) {
            DDWAF_DEBUG("Replacing {} target '{}' in object store",
                scope.is_subcontext() ? "subcontext" : "context", key);
        } else {
            DDWAF_DEBUG("Inserting {} target '{}' into object store",
                scope.is_subcontext() ? "subcontext" : "context", key);
        }

        objects_[target] = {view, scope};
        latest_batch_.emplace(target);

        return true;
    }

    evaluation_scope scope_;
    memory::list<owned_object> input_objects_;

    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, std::pair<object_view, evaluation_scope>> objects_;
};

} // namespace ddwaf
