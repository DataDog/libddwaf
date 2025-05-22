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

namespace ddwaf {

/**
 * @brief A class for collecting and managing attributes from various sources.
 *
 * The attribute_collector is responsible for gathering attributes from different sources,
 * such as processors and rules, and maintaining them in a structured format. It provides methods
 * to insert various types of attributes (strings, numbers, booleans) and collect attributes
 * from the object store based on specified target addresses and key paths.
 *
 * The collector also maintains a queue of pending attributes which are to be collected
 * from the object store if unavailable when the caller performs a collection. This can be done
 * through the use of the `collect_pending` method.
 *
 * The class is not copyable or moveable to ensure proper resource management.
 */
class attribute_collector {
public:
    attribute_collector() { ddwaf_object_map(&attributes_); }
    attribute_collector(const attribute_collector &) = delete;
    attribute_collector &operator=(const attribute_collector &) = delete;
    attribute_collector(attribute_collector &&other) noexcept = delete;
    attribute_collector &operator=(attribute_collector &&other) noexcept = delete;
    ~attribute_collector() { ddwaf_object_free(&attributes_); }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool insert(std::string_view key, std::string_view value)
    {
        ddwaf_object object;
        ddwaf_object_stringl(&object, value.data(), value.size());
        return insert(key, object, false);
    }

    bool insert(std::string_view key, uint64_t value)
    {
        ddwaf_object object;
        ddwaf_object_unsigned(&object, value);
        return insert(key, object, false);
    }

    bool insert(std::string_view key, int64_t value)
    {
        ddwaf_object object;
        ddwaf_object_signed(&object, value);
        return insert(key, object, false);
    }

    bool insert(std::string_view key, double value)
    {
        ddwaf_object object;
        ddwaf_object_float(&object, value);
        return insert(key, object, false);
    }

    bool insert(std::string_view key, bool value)
    {
        ddwaf_object object;
        ddwaf_object_bool(&object, value);
        return insert(key, object, false);
    }

    bool insert(std::string_view key, const ddwaf_object &value, bool copy);

    bool collect(const object_store &store, target_index input_target,
        std::span<const std::string> input_key_path, std::string_view attribute_key);

    void collect_pending(const object_store &store);

    // This method returns the object map containing all the inserted and
    // collected attributes and resets both the internal object (to an empty map)
    // and the list of previously collected attributes.
    ddwaf_object get_available_attributes_and_reset()
    {
        auto output_object = attributes_;
        // Reset attributes
        ddwaf_object_map(&attributes_);
        inserted_or_pending_attributes_.clear();

        return output_object;
    }

    // Only used for testing
    [[nodiscard]] bool has_pending_attributes() const { return !pending_.empty(); }

protected:
    enum class collection_state : uint8_t { success, unavailable, failed };

    collection_state collect_helper(const object_store &store, target_index input_target,
        std::span<const std::string> input_key_path, std::string_view attribute_key);
    bool insert_helper(std::string_view key, const ddwaf_object &value, bool copy);

    // The views and spans used here are owned by rules and processors, these
    // are part of their definition and are unchanging during the lifetime of
    // the context, therefore it's safe to use them..
    // In this pair, the target_index represents the required address and the
    // string span represents the key path.
    using target_type = std::pair<target_index, std::span<const std::string>>;
    std::unordered_map<std::string_view, target_type> pending_;

    std::unordered_set<std::string_view> inserted_or_pending_attributes_;
    ddwaf_object attributes_{};
};

} // namespace ddwaf
