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
#include <vector>

#include <clock.hpp>
#include <context_allocator.hpp>
#include <event.hpp>
#include <iterator.hpp>
#include <object_store.hpp>
#include <operation/base.hpp>

#include "transformer/manager.hpp"

namespace ddwaf {

class condition {
public:
    using ptr = std::shared_ptr<condition>;

    enum class data_source : uint8_t { values, keys };

    struct target_type {
        target_index root;
        std::string name;
        std::vector<std::string> key_path{};
        std::vector<transformer_id> transformers{};
        data_source source{data_source::values};
    };

    condition(std::vector<target_type> targets, std::shared_ptr<operation::base> processor,
        std::string data_id = {}, ddwaf::object_limits limits = ddwaf::object_limits())
        : targets_(std::move(targets)), processor_(std::move(processor)),
          data_id_(std::move(data_id)), limits_(limits)
    {}

    ~condition() = default;
    condition(condition &&) = default;
    condition &operator=(condition &&) = default;

    condition(const condition &) = delete;
    condition &operator=(const condition &) = delete;

    std::optional<event::match> match(const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded, bool run_on_new,
        const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const;

    [[nodiscard]] const std::vector<condition::target_type> &get_targets() const
    {
        return targets_;
    }

protected:
    std::optional<event::match> match_object(const ddwaf_object *object,
        const operation::base::ptr &processor,
        const std::vector<transformer_id> &transformers) const;

    template <typename T>
    std::optional<event::match> match_target(T &it, const operation::base::ptr &processor,
        const std::vector<transformer_id> &transformers, ddwaf::timer &deadline) const;

    [[nodiscard]] const operation::base::ptr &get_processor(
        const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors) const;
    std::vector<condition::target_type> targets_;
    std::shared_ptr<operation::base> processor_;
    std::string data_id_;
    ddwaf::object_limits limits_;
};

} // namespace ddwaf
