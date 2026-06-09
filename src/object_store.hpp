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

namespace ddwaf {

class object_store {
public:
    object_store() = default;

    ~object_store() = default;
    object_store(const object_store &other) = delete;
    object_store(object_store &&) = default;
    object_store &operator=(const object_store &other) = delete;
    object_store &operator=(object_store &&) = default;

    // Enqueue a single batch of input addresses (a map). The batch is not
    // applied to the store until consumed via next_batch(); a batch with no
    // addresses is accepted as a harmless no-op. Returns false if the object is
    // not a map.
    bool insert_batch(owned_object &&input);
    bool insert_batch(map_view input);

    // Enqueue a sequence of input batches: an array whose every element is a
    // map, each queued as a separate batch. Returns false if the object is not
    // an array or any element is not a map.
    bool insert_batches(owned_object &&input);
    bool insert_batches(array_view input);
    // Insert a single derived target (e.g. produced by a processor) directly,
    // marking it as new. Unlike the batch insert overloads above this takes
    // effect immediately rather than being queued.
    bool insert_target(target_index target, std::string_view key, owned_object &&input);

    // Consume the next queued input batch, applying its addresses to the store
    // and marking them as new. Returns false once the queue is drained.
    bool next_batch();

    // Enqueue and immediately apply a single batch. Used for testing only.
    bool insert_and_apply(owned_object &&input)
    {
        if (!insert_batch(std::move(input))) {
            return false;
        }
        next_batch();
        return true;
    }
    bool insert_and_apply(map_view input)
    {
        insert_batch(input);
        next_batch();
        return true;
    }

    // Apply any remaining queued batches as targets *without* marking them as
    // new (so they won't be evaluated) and clear the new-target set. Invoked
    // once evaluation finishes, on any exit path including a timeout, mirroring
    // the inputs being carried over to a subsequent ddwaf_context_eval call.
    void flush_input_queue();

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
    // Append a single input batch to the queue, ignoring empty batches.
    void enqueue_batch(map_view input);

    // Apply a single input batch's addresses to the store. When mark_new is
    // true the addresses are added to the new-target set and will be evaluated.
    void apply_batch(map_view input, bool mark_new);

    memory::list<owned_object> input_objects_;

    memory::list<map_view> object_queue_;
    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, object_view> targets_;
};

} // namespace ddwaf
