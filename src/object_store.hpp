// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "context_allocator.hpp"
#include "log.hpp"
#include "object.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

class base_object_store {
public:
    base_object_store() = default;
    virtual ~base_object_store() = default;
    base_object_store(const base_object_store &) = default;
    base_object_store(base_object_store &&) = default;
    base_object_store &operator=(const base_object_store &) = delete;
    base_object_store &operator=(base_object_store &&) = delete;

    virtual bool insert(owned_object &&input) = 0;
    virtual bool insert(target_index target, std::string_view key, owned_object &&input) = 0;
    virtual bool insert(map_view input) = 0;

    [[nodiscard]] virtual std::pair<object_view, evaluation_scope> get_target(
        target_index target) const = 0;
    [[nodiscard]] virtual std::pair<object_view, evaluation_scope> get_target(
        std::string_view name) const = 0;

    [[nodiscard]] virtual bool has_target(target_index target) const = 0;
    [[nodiscard]] virtual bool is_new_target(target_index target) const = 0;
    [[nodiscard]] virtual bool has_new_targets() const = 0;
    [[nodiscard]] virtual bool empty() const = 0;
    virtual void clear_last_batch() = 0;
};

template <typename Self> class base_object_store_impl : public base_object_store {
public:
    ~base_object_store_impl() override = default;
    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    base_object_store_impl(const base_object_store_impl &) = delete;
    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    base_object_store_impl(base_object_store_impl &&) = delete;
    base_object_store_impl &operator=(const base_object_store_impl &) = delete;
    base_object_store_impl &operator=(base_object_store_impl &&) = delete;

    bool insert(owned_object &&input) override
    {
        object_view view = underlying_object()->input_objects_.emplace_back(std::move(input));
        if (!view.is_map()) {
            return false;
        }

        return insert(view);
    }

    bool insert(map_view input) override
    {
        const auto size = input.size();
        if (size == 0) {
            // Objects with no addresses are considered valid as they are harmless
            return true;
        }

        underlying_object()->objects_.reserve(underlying_object()->objects_.size() + size);
        underlying_object()->latest_batch_.reserve(
            underlying_object()->latest_batch_.size() + size);

        for (std::size_t i = 0; i < size; ++i) {
            auto [key_obj, value] = input.at(i);
            if (key_obj.empty()) {
                continue;
            }

            auto key = key_obj.as<std::string_view>();
            auto target = get_target_index(key);
            insert_target_helper(target, key, value, underlying_object()->scope_);
        }

        return true;
    }

    bool insert(target_index target, std::string_view key, owned_object &&input) override
    {
        object_view view = underlying_object()->input_objects_.emplace_back(std::move(input));

        return insert_target_helper(target, key, view, underlying_object()->scope_);
    }

    [[nodiscard]] std::pair<object_view, evaluation_scope> get_target(
        target_index target) const override
    {
        auto it = underlying_object()->objects_.find(target);
        if (it != underlying_object()->objects_.end()) {
            return {it->second.first, it->second.second};
        }
        return {nullptr, evaluation_scope::context()};
    }

    // Used for testing
    [[nodiscard]] std::pair<object_view, evaluation_scope> get_target(
        std::string_view name) const override
    {
        return get_target(get_target_index(name));
    }

    [[nodiscard]] bool has_target(target_index target) const override
    {
        return underlying_object()->objects_.contains(target);
    }
    [[nodiscard]] bool is_new_target(const target_index target) const override
    {
        return underlying_object()->latest_batch_.contains(target);
    }
    [[nodiscard]] bool has_new_targets() const override
    {
        return !underlying_object()->latest_batch_.empty();
    }
    [[nodiscard]] bool empty() const override { return underlying_object()->objects_.empty(); }
    void clear_last_batch() override { underlying_object()->latest_batch_.clear(); }

private:
    base_object_store_impl() = default;

    Self *underlying_object() { return static_cast<Self *>(this); }

    [[nodiscard]] const Self *underlying_object() const { return static_cast<const Self *>(this); }

    bool insert_target_helper(
        target_index target, std::string_view key, object_view view, evaluation_scope scope)
    {
        if (underlying_object()->objects_.contains(target)) {
            DDWAF_DEBUG("Replacing {} target '{}' in object store",
                scope.is_subcontext() ? "subcontext" : "context", key);
        } else {
            DDWAF_DEBUG("Inserting {} target '{}' into object store",
                scope.is_subcontext() ? "subcontext" : "context", key);
        }

        underlying_object()->objects_[target] = {view, scope};
        underlying_object()->latest_batch_.emplace(target);

        return true;
    }

    friend Self;
};

class subcontext_object_store;

class object_store : public base_object_store_impl<object_store> {
public:
    object_store() = default;
    ~object_store() override = default;
    object_store(const object_store &) = delete;
    object_store(object_store &&) = delete;
    object_store &operator=(const object_store &) = delete;
    object_store &operator=(object_store &&) = delete;

protected:
    evaluation_scope scope_{evaluation_scope::context()};
    memory::list<owned_object> input_objects_;

    memory::unordered_set<target_index> latest_batch_;
    memory::unordered_map<target_index, std::pair<object_view, evaluation_scope>> objects_;

    friend class base_object_store_impl<object_store>;
    friend class subcontext_object_store;
};

class subcontext_object_store : public base_object_store_impl<subcontext_object_store> {
public:
    explicit subcontext_object_store(const object_store &upstream, evaluation_scope scope)
        : scope_(scope)
    {
        for (const auto &[target, object_and_scope] : upstream.objects_) {
            objects_.emplace(target, object_and_scope);
        }
    }

    ~subcontext_object_store() override = default;
    subcontext_object_store(const subcontext_object_store &) = delete;
    subcontext_object_store(subcontext_object_store &&) = delete;
    subcontext_object_store &operator=(const subcontext_object_store &) = delete;
    subcontext_object_store &operator=(subcontext_object_store &&) = delete;

protected:
    evaluation_scope scope_;
    std::list<owned_object> input_objects_;

    std::unordered_set<target_index> latest_batch_;
    std::unordered_map<target_index, std::pair<object_view, evaluation_scope>> objects_;

    friend class base_object_store_impl<subcontext_object_store>;
};

} // namespace ddwaf
