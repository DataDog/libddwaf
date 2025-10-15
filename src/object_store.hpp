// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "object.hpp"
#include "target_address.hpp"

namespace ddwaf {

class object_store {
public:
    object_store() = default;

    ~object_store() = default;
    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    object_store(const object_store &other)
        : latest_batch_(other.latest_batch_), objects_(other.objects_)
    {}

    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    object_store(object_store &&) = default;

    object_store &operator=(const object_store &other)
    {
        if (&other == this) {
            return *this;
        }

        latest_batch_ = other.latest_batch_;
        objects_ = other.objects_;
        return *this;
    }

    object_store &operator=(object_store &&) = default;

    bool insert(owned_object &&input);
    bool insert(map_view input);
    bool insert(target_index target, std::string_view key, owned_object &&input);

    [[nodiscard]] object_view get_target(target_index target) const
    {
        auto it = objects_.find(target);
        if (it != objects_.end()) {
            return it->second;
        }
        return nullptr;
    }

    // Used for testing
    [[nodiscard]] object_view get_target(std::string_view name) const
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

private:
    bool insert_target_helper(target_index target, std::string_view key, object_view view);

    memory::list<owned_object> input_objects_;

    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, object_view> objects_;
};

} // namespace ddwaf
