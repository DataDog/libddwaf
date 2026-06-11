// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "object.hpp"
#include "target_address.hpp"
#include <string_view>
#include <utility>

namespace ddwaf {

class object_store {
public:
    object_store() = default;

    ~object_store() = default;
    object_store(const object_store &other) = delete;
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &other) = delete;
    object_store &operator=(object_store &&) = default;

    // Take ownership of an input object so that views into it remain valid for
    // the lifetime of the store; returns a view over the stored object. This
    // registers no targets.
    object_view insert(owned_object &&input)
    {
        return input_objects_.emplace_back(std::move(input));
    }

    // Apply a batch of addresses (a map) to the store's targets. When mark_new
    // is true the addresses are added to the new-target set and will be
    // evaluated. The map must be backed by storage that outlives the store
    // (e.g. an object owned via insert, or caller-owned input).
    void apply(map_view batch, bool mark_new = true);

    // Own and apply a single batch as a self-contained unit: the previous
    // new-target set is reset first, then the batch is applied as new. An empty
    // batch only performs the reset. Returns false if the object is not a map.
    bool insert_and_apply(owned_object &&input)
    {
        const object_view view = insert(std::move(input));
        if (!view.is_map()) {
            return false;
        }
        return insert_and_apply(map_view{view});
    }

    bool insert_and_apply(map_view input)
    {
        clear_latest_batch();
        apply(input, /*mark_new=*/true);
        return true;
    }

    // Own and register a single derived target (e.g. produced by a processor),
    // flagging it as new. Unlike insert_and_apply this does not reset the
    // new-target set, since derived targets accumulate within the current batch.
    bool insert_and_apply(target_index target, std::string_view key, owned_object &&input)
    {
        register_target(target, key, insert(std::move(input)), /*mark_new=*/true);
        return true;
    }

    // Reset the new-target set at a batch boundary so the next batch can
    // identify newly-provided addresses; the targets themselves are retained.
    void clear_latest_batch() { latest_batch_.clear(); }

    [[nodiscard]] object_view get_target(target_index target) const
    {
        auto it = targets_.find(target);
        if (it != targets_.end()) {
            return it->second;
        }
        return nullptr;
    }

    // Used for testing
    [[nodiscard]] object_view get_target(std::string_view name) const
    {
        return get_target(get_target_index(name));
    }

    [[nodiscard]] bool has_target(target_index target) const { return targets_.contains(target); }
    [[nodiscard]] bool is_new_target(const target_index target) const
    {
        return latest_batch_.contains(target);
    }
    [[nodiscard]] bool has_new_targets() const { return !latest_batch_.empty(); }
    [[nodiscard]] bool empty() const { return targets_.empty(); }

    // An object store created from an upstream store assumes that the original
    // store retains ownership and will outlive this store, therefore only the
    // targets are copied.
    static object_store from_upstream_store(const object_store &upstream)
    {
        object_store store;
        store.latest_batch_ = upstream.latest_batch_;
        store.targets_ = upstream.targets_;
        return store;
    }

private:
    // Register a single resolved target, optionally flagging it as new. Shared
    // by apply and insert_and_apply.
    void register_target(
        target_index target, std::string_view key, object_view value, bool mark_new);

    memory::list<owned_object> input_objects_;
    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, object_view> targets_;
};

} // namespace ddwaf
