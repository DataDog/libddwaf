// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <string_view>
#include <utility>

#include "log.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "target_address.hpp"

namespace ddwaf {

bool object_store::insert_batch(owned_object &&input)
{
    // The input object retains ownership of the enqueued batch, so it must
    // outlive the queue.
    const object_view view = input_objects_.emplace_back(std::move(input));
    if (!view.is_map()) {
        return false;
    }

    enqueue_batch(view);
    return true;
}

bool object_store::insert_batch(map_view input)
{
    enqueue_batch(input);
    return true;
}

bool object_store::insert_batches(array_view input)
{
    // An array represents a sequence of input batches; every element must
    // itself be a map of addresses - validate all of them before enqueueing so
    // that a failure leaves the queue untouched.
    for (auto element : input) {
        if (!element.is_map()) {
            return false;
        }
    }

    for (auto element : input) { enqueue_batch(element); }

    return true;
}

bool object_store::insert_batches(owned_object &&input)
{
    // The input object retains ownership of every enqueued batch, so it must
    // outlive the queue.
    const object_view view = input_objects_.emplace_back(std::move(input));
    if (!view.is_array()) {
        return false;
    }

    return insert_batches(array_view{view});
}

void object_store::enqueue_batch(map_view input)
{
    // Batches with no addresses are considered valid as they are harmless
    if (!input.empty()) {
        object_queue_.emplace_back(input);
    }
}

bool object_store::next_batch()
{
    if (object_queue_.empty()) {
        return false;
    }

    apply_batch(object_queue_.front(), /*mark_new=*/true);
    object_queue_.pop_front();
    return true;
}

void object_store::flush_input_queue()
{
    if (!object_queue_.empty()) {
        DDWAF_DEBUG("Flushing remaining queued objects");
        for (auto input : object_queue_) { apply_batch(input, /*mark_new=*/false); }
        object_queue_.clear();
    }

    latest_batch_.clear();
}

void object_store::apply_batch(map_view input, bool mark_new)
{
    const auto size = input.size();
    targets_.reserve(targets_.size() + size);
    if (mark_new) {
        latest_batch_.reserve(latest_batch_.size() + size);
    }

    for (std::size_t i = 0; i < size; ++i) {
        auto [key_obj, value] = input.at(i);
        if (key_obj.empty()) {
            continue;
        }

        auto key = key_obj.as<std::string_view>();
        auto target = get_target_index(key);

        if (targets_.contains(target)) {
            DDWAF_DEBUG("Replacing target '{}' in object store", key);
        } else {
            DDWAF_DEBUG("Inserting target '{}' into object store", key);
        }

        targets_[target] = value;
        if (mark_new) {
            latest_batch_.emplace(target);
        }
    }
}

bool object_store::insert_target(target_index target, std::string_view key, owned_object &&input)
{
    const object_view view = input_objects_.emplace_back(std::move(input));

    if (targets_.contains(target)) {
        DDWAF_DEBUG("Replacing target '{}' in object store", key);
    } else {
        DDWAF_DEBUG("Inserting target '{}' into object store", key);
    }

    targets_[target] = view;
    latest_batch_.emplace(target);

    return true;
}

} // namespace ddwaf
