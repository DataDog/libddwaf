// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "object.hpp"
#include "target_address.hpp"
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace ddwaf {

// Set of targets, as a bitset indexed by target (see target_index)
class target_set {
public:
    [[nodiscard]] bool contains(target_index target) const
    {
        const auto word = target / word_bits;
        return word < words_.size() && (words_[word] & bit(target)) != 0;
    }

    [[nodiscard]] bool empty() const { return empty_; }

    // Calls fn with each target in the set, in increasing order
    template <typename Fn> void for_each(Fn &&fn) const
    {
        if (empty_) {
            return;
        }

        for (std::size_t i = 0; i < words_.size(); ++i) {
            for (auto word = words_[i]; word != 0; word &= word - 1) {
                fn(static_cast<target_index>((i * word_bits) + std::countr_zero(word)));
            }
        }
    }

    // The set must have been resized to contain the target
    void insert(target_index target)
    {
        words_[target / word_bits] |= bit(target);
        empty_ = false;
    }

    void clear()
    {
        if (!empty_) {
            std::fill(words_.begin(), words_.end(), 0);
            empty_ = true;
        }
    }

    // Ensures that targets lower than count can be inserted
    void resize(std::size_t count) { words_.resize((count + word_bits - 1) / word_bits); }

protected:
    static constexpr std::size_t word_bits = 64;

    static uint64_t bit(target_index target) { return uint64_t{1} << (target % word_bits); }

    memory::vector<uint64_t> words_;
    bool empty_{true};
};

class object_store {
public:
    // The addresses of input batches are resolved through the lookup, which
    // must outlive the store; those which aren't in it are ignored, as no
    // component can refer to them. Without a lookup (meant for testing),
    // every address is registered as with get_target_index.
    explicit object_store(const target_lookup *lookup = nullptr) : lookup_(lookup) {}

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
        if (target < targets_.size()) {
            return targets_[target];
        }
        return nullptr;
    }

    // Used for testing
    [[nodiscard]] object_view get_target(std::string_view name) const
    {
        return get_target(get_target_index(name));
    }

    [[nodiscard]] bool has_target(target_index target) const
    {
        return get_target(target).has_value();
    }
    [[nodiscard]] bool is_new_target(const target_index target) const
    {
        return latest_batch_.contains(target);
    }
    [[nodiscard]] bool has_new_targets() const { return !latest_batch_.empty(); }
    [[nodiscard]] bool empty() const { return target_count_ == 0; }

    // Targets registered or replaced since the last call to clear_updated_targets,
    // whether or not they were flagged as new (e.g. flushed batches). Unlike
    // the new-target set, this is not reset at batch boundaries: it allows the
    // consumer to find out which targets have changed since it last looked at
    // the store.
    [[nodiscard]] const target_set &updated_targets() const { return updated_targets_; }
    void clear_updated_targets() { updated_targets_.clear(); }

    // An object store created from an upstream store assumes that the original
    // store retains ownership and will outlive this store, therefore only the
    // targets are copied.
    static object_store from_upstream_store(const object_store &upstream)
    {
        object_store store;
        store.lookup_ = upstream.lookup_;
        store.targets_ = upstream.targets_;
        store.latest_batch_ = upstream.latest_batch_;
        store.updated_targets_ = upstream.updated_targets_;
        store.target_count_ = upstream.target_count_;
        return store;
    }

private:
    // Register a single resolved target, optionally flagging it as new. Shared
    // by apply and insert_and_apply.
    void register_target(
        target_index target, std::string_view key, object_view value, bool mark_new);

    // Ensures that targets lower than count can be registered
    void reserve_targets(std::size_t count)
    {
        targets_.resize(count);
        latest_batch_.resize(count);
        updated_targets_.resize(count);
    }

    const target_lookup *lookup_{nullptr};
    memory::list<owned_object> input_objects_;
    // Indexed by target, an absent target has no value
    memory::vector<object_view> targets_;
    // Targets of the current batch
    target_set latest_batch_;
    target_set updated_targets_;
    std::size_t target_count_{0};
};

} // namespace ddwaf
