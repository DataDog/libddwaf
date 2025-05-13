// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <span>
#include <string_view>
#include <unordered_map>

#include "object_store.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

class attribute_collector {
public:
    attribute_collector() { ddwaf_object_map(&attributes_); }

    // This method can be split in two in v2  and avoid the copy flag
    bool emplace(std::string_view key, const ddwaf_object &value, bool copy);

    void collect(const object_store &store, target_index input_target,
        std::span<std::string> input_key_path, std::string_view output);

    void collect_pending(const object_store &store);

    ddwaf_object move_current_batch()
    {
        auto res = attributes_;
        ddwaf_object_map(&attributes_);
        return res;
    }

protected:
    enum class collection_state : uint8_t { success, unavailable, failed };

    collection_state collect_helper(const object_store &store, target_index input_target,
        std::span<std::string> input_key_path, std::string_view output);

    using target_type = std::pair<target_index, std::span<std::string>>;
    std::unordered_map<std::string_view, target_type> pending_;

    std::unordered_set<std::string_view> emplaced_attributes_;
    ddwaf_object attributes_{};
};

} // namespace ddwaf
