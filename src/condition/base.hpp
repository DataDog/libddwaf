// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf::condition {

enum class data_source : uint8_t { values, keys, object };

enum class object_type : uint8_t {
    boolean = DDWAF_OBJ_BOOL,
    integer = DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED,
    real = DDWAF_OBJ_FLOAT,
    string = DDWAF_OBJ_STRING,
    array = DDWAF_OBJ_ARRAY,
    map = DDWAF_OBJ_MAP,
    container = map | array,
    scalar = boolean | integer | real | string,
    any = container | scalar,
};

// Provides information about the arguments allowed by the condition
struct argument_specification {
    std::string_view name;
    object_type type;
    bool variadic{false};
    bool optional{false};
};

// Provides the definition of the arguments for an instance of the condition,
// each argument definition must satisfy the argument specification.
struct target_definition {
    std::string name;
    target_index root{};
    std::vector<std::string> key_path{};
    std::vector<transformer_id> transformers{};
    data_source source{data_source::values};
};

struct argument_definition {
    std::vector<target_definition> targets;
};

struct cache_type {
    // The targets cache mirrors the array of targets for the given condition.
    // Each element in this array caches the pointer of the last non-ephemeral
    // object evaluated by the target in the same index within the condition.
    memory::vector<ddwaf_object *> targets;
    std::optional<event::match> match;
};

class base {
public:
    base() = default;
    virtual ~base() = default;
    base(const base &) = default;
    base(base &&) noexcept = default;
    base &operator=(const base &) = default;
    base &operator=(base &&) noexcept = default;

    virtual eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline) const = 0;

    virtual void get_addresses(std::unordered_map<target_index, std::string> &addresses) const = 0;
};

template <typename T>
class base_impl : public base {
public:
    explicit base_impl(std::vector<argument_definition> args): arguments_(std::move(args)) {
        auto definitions = T::arguments();

        if (definitions.size() != arguments_.size()) {
            throw std::invalid_argument("incorrect definition of condition");
        }

        for (unsigned i = 0; i < arguments_.size(); ++i) {
            const auto &def = definitions[i];
            const auto &arg = arguments_[i];

            if (!def.variadic && arg.targets.size() > 1) {
                throw std::invalid_argument("non-variadic argument used as variadic");
            }
        }
    }

    ~base_impl() override = default;
    base_impl(const base_impl &) = default;
    base_impl(base_impl &&) noexcept = default;
    base_impl &operator=(const base_impl &) = default;
    base_impl &operator=(base_impl &&) noexcept = default;

    eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline) const override
    {
        return static_cast<const T*>(this)->eval_impl(
                cache, store, objects_excluded, dynamic_matchers, limits, deadline);
    }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const override
    {
        for (const auto &arg : arguments_) {
            for (const auto &target : arg.targets) {
                addresses.emplace(target.root, target.name);
            }
        }
    }
protected:
    std::vector<argument_definition> arguments_;
};

} // namespace ddwaf::condition
