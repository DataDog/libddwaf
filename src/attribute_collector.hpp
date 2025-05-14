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
    attribute_collector(const attribute_collector &) = delete;
    attribute_collector &operator=(const attribute_collector &) = delete;
    attribute_collector(attribute_collector &&) = delete;
    attribute_collector &operator=(attribute_collector &&) = delete;
    ~attribute_collector() { ddwaf_object_free(&attributes_); }

    bool emplace(std::string_view key, const ddwaf_object &value, bool copy);

    void collect(const object_store &store, target_index input_target,
        std::span<std::string> input_key_path, std::string_view output);

    ddwaf_object collect_pending(const object_store &store);

protected:
    enum class collection_state : uint8_t { success, unavailable, failed };

    collection_state collect_helper(const object_store &store, target_index input_target,
        std::span<std::string> input_key_path, std::string_view output);
    bool emplace_helper(std::string_view key, const ddwaf_object &value, bool copy);

    // The views and spans used here are owned by rules and processors, these
    // are part of their definition and are unchanging during the lifetime of
    // the context, therefore it's safe to use them.
    using target_type = std::pair<target_index, std::span<std::string>>;
    std::unordered_map<std::string_view, target_type> pending_;

    std::unordered_set<std::string_view> emplaced_attributes_;
    ddwaf_object attributes_{};
};

} // namespace ddwaf
