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
    attribute_collector(attribute_collector &&) = default;
    attribute_collector &operator=(attribute_collector &&) = delete;
    ~attribute_collector() { ddwaf_object_free(&attributes_); }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool emplace(std::string_view key, std::string_view value)
    {
        ddwaf_object object;
        ddwaf_object_stringl(&object, value.data(), value.size());
        return emplace(key, object, false);
    }

    bool emplace(std::string_view key, uint64_t value)
    {
        ddwaf_object object;
        ddwaf_object_unsigned(&object, value);
        return emplace(key, object, false);
    }

    bool emplace(std::string_view key, int64_t value)
    {
        ddwaf_object object;
        ddwaf_object_signed(&object, value);
        return emplace(key, object, false);
    }

    bool emplace(std::string_view key, double value)
    {
        ddwaf_object object;
        ddwaf_object_float(&object, value);
        return emplace(key, object, false);
    }

    bool emplace(std::string_view key, bool value)
    {
        ddwaf_object object;
        ddwaf_object_bool(&object, value);
        return emplace(key, object, false);
    }

    bool emplace(std::string_view key, const ddwaf_object &value, bool copy);

    void collect(const object_store &store, target_index input_target,
        std::span<const std::string> input_key_path, std::string_view output);

    void collect_pending(const object_store &store);

    [[nodiscard]] bool has_pending_attributes() const { return !pending_.empty(); }

    ddwaf_object get_available_attributes()
    {
        auto output_object = attributes_;
        // Reset attributes
        ddwaf_object_map(&attributes_);
        emplaced_attributes_.clear();

        return output_object;
    }

protected:
    enum class collection_state : uint8_t { success, unavailable, failed };

    collection_state collect_helper(const object_store &store, target_index input_target,
        std::span<const std::string> input_key_path, std::string_view output);
    bool emplace_helper(std::string_view key, const ddwaf_object &value, bool copy);

    // The views and spans used here are owned by rules and processors, these
    // are part of their definition and are unchanging during the lifetime of
    // the context, therefore it's safe to use them.
    using target_type = std::pair<target_index, std::span<const std::string>>;
    std::unordered_map<std::string_view, target_type> pending_;

    std::unordered_set<std::string_view> emplaced_attributes_;
    ddwaf_object attributes_{};
};

} // namespace ddwaf
