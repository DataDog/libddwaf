// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "log.hpp"
#include "object.hpp"
#include "object_store.hpp"

namespace ddwaf {

// Manages the sequence of input batches fed into an object_store during an
// evaluation. Batches are enqueued (validated but not applied) and later
// consumed one at a time via next_batch(); each batch is evaluated as if it
// were a separate eval call. Any batch left unconsumed when evaluation finishes
// is flushed into the store as non-new data, mirroring the inputs being carried
// over to a subsequent eval call.
//
// The owning input objects are parked in the object_store rather than the queue
// so that views into them remain valid for the (potentially shared) lifetime of
// the store, while the queue itself only holds transient views.
class input_batch_queue {
public:
    input_batch_queue() = default;
    ~input_batch_queue() = default;
    input_batch_queue(const input_batch_queue &) = delete;
    input_batch_queue &operator=(const input_batch_queue &) = delete;
    input_batch_queue(input_batch_queue &&) = default;
    input_batch_queue &operator=(input_batch_queue &&) = default;

    // Enqueue a single batch of input addresses (a map). The owning object is
    // parked in the store so that views into it remain valid. A batch with no
    // addresses is accepted as a harmless no-op. Returns false if the object is
    // not a map.
    bool insert_batch(object_store &store, owned_object &&input)
    {
        const object_view view = store.insert(std::move(input));
        if (!view.is_map()) {
            return false;
        }
        enqueue(view);
        return true;
    }

    bool insert_batch(object_store & /*store*/, map_view input)
    {
        enqueue(input);
        return true;
    }

    // Enqueue a sequence of input batches: an array whose every element is a
    // map, each queued as a separate batch. Returns false if the object is not
    // an array or any element is not a map; on failure the queue is left
    // untouched.
    bool insert_batches(object_store &store, owned_object &&input)
    {
        const object_view view = store.insert(std::move(input));
        if (!view.is_array()) {
            return false;
        }
        return insert_batches(store, array_view{view});
    }

    bool insert_batches(object_store & /*store*/, array_view input)
    {
        // Validate every element before enqueueing anything so that a failure
        // leaves the queue untouched.
        for (auto element : input) {
            if (!element.is_map()) {
                return false;
            }
        }

        for (auto element : input) { enqueue(element); }

        return true;
    }

    // Consume the next queued input batch, applying its addresses to the store
    // and marking them as new. The previous batch's new-target set is reset
    // first so each batch is evaluated as if it were a separate eval call.
    // Returns false once the queue is drained.
    bool next_batch(object_store &store)
    {
        store.clear_latest_batch();

        if (queue_.empty()) {
            return false;
        }

        store.apply(queue_.front(), /*mark_new=*/true);
        queue_.pop_front();
        return true;
    }

    // Apply any remaining queued batches to the store *without* marking them as
    // new (so they won't be evaluated) and reset the new-target set. Invoked
    // once evaluation finishes, on any exit path including a timeout.
    void flush(object_store &store)
    {
        if (!queue_.empty()) {
            DDWAF_DEBUG("Flushing remaining queued objects");
            for (auto input : queue_) { store.apply(input, /*mark_new=*/false); }
            queue_.clear();
        }

        store.clear_latest_batch();
    }

    [[nodiscard]] bool empty() const { return queue_.empty(); }

private:
    // Append a single input batch to the queue.
    void enqueue(map_view input) { queue_.emplace_back(input); }

    memory::list<map_view> queue_;
};

} // namespace ddwaf
