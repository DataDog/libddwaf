// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <context_allocator.hpp>
#include <ddwaf.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utils.hpp>

namespace ddwaf {

class object_store {
public:
    enum class attribute : uint8_t { none = 0, immutable = 1 /*, ephemeral = 2 */ };

    using object_and_attribute = std::pair<ddwaf_object *, attribute>;

    object_store() = default;
    ~object_store();
    object_store(const object_store &) = default;
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &) = delete;
    object_store &operator=(object_store &&) = delete;

    bool insert(ddwaf_object &input, ddwaf_object_free_fn free_fn = ddwaf_object_free,
        attribute attr = attribute::none);
    // This function doesn't clear the latest batch
    bool insert(target_index target, ddwaf_object &input,
        ddwaf_object_free_fn free_fn = ddwaf_object_free, attribute attr = attribute::none);
    object_and_attribute get_target(target_index target) const;

    bool has_target(target_index target) const { return objects_.find(target) != objects_.end(); }

    bool is_new_target(const target_index target) const
    {
        return latest_batch_.find(target) != latest_batch_.cend();
    }

    bool has_new_targets() const { return !latest_batch_.empty(); }

    explicit operator bool() const { return !objects_.empty(); }

protected:
    memory::list<std::pair<ddwaf_object, ddwaf_object_free_fn>> input_objects_;

    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, object_and_attribute> objects_;
};

inline constexpr object_store::attribute operator|(
    object_store::attribute lhs, object_store::attribute rhs)
{
    return static_cast<object_store::attribute>(
        static_cast<std::underlying_type<object_store::attribute>::type>(lhs) |
        static_cast<std::underlying_type<object_store::attribute>::type>(rhs));
}

inline constexpr object_store::attribute operator&(
    object_store::attribute lhs, object_store::attribute rhs)
{
    return static_cast<object_store::attribute>(
        static_cast<std::underlying_type<object_store::attribute>::type>(lhs) &
        static_cast<std::underlying_type<object_store::attribute>::type>(rhs));
}

} // namespace ddwaf
