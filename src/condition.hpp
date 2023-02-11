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

#include <PWTransformer.h>
#include <clock.hpp>
#include <event.hpp>
#include <iterator.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule_processor/base.hpp>

namespace ddwaf {

class condition {
public:
    using ptr = std::shared_ptr<condition>;
    struct target_type {
        manifest::target_type root;
        std::string name;
        std::vector<std::string> key_path;
    };

    enum class data_source : uint8_t { values, keys };

    condition(std::vector<target_type> &&targets,
        std::vector<PW_TRANSFORM_ID> &&transformers,
        std::shared_ptr<rule_processor::base> &&processor,
        ddwaf::object_limits limits = ddwaf::object_limits(),
        data_source source = data_source::values, bool is_mutable = false)
        : targets_(std::move(targets)), transformers_(std::move(transformers)),
          processor_(std::move(processor)), limits_(limits), source_(source), mutable_(is_mutable)
    {}

    ~condition() = default;
    condition(condition &&) = default;
    condition &operator=(condition &&) = default;

    condition(const condition &) = delete;
    condition &operator=(const condition &) = delete;

    std::optional<event::match> match(const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        bool run_on_new, ddwaf::timer &deadline) const;

    std::string_view processor_name()
    {
        if (mutable_) {
            return std::atomic_load(&processor_)->name();
        }

        return processor_->name();
    }

    void reset_processor(std::shared_ptr<rule_processor::base> &proc)
    {
        if (!mutable_) {
            throw std::runtime_error("Attempting to mutate an immutable "
                                     "condition with processor " +
                                     std::string(processor_->name()));
        }

        std::atomic_store(&processor_, proc);
    }

protected:
    std::optional<event::match> match_object(const ddwaf_object *object) const;

    template <typename T>
    std::optional<event::match> match_target(T &it, ddwaf::timer &deadline) const;

    std::vector<target_type> targets_;
    std::vector<PW_TRANSFORM_ID> transformers_;
    std::shared_ptr<rule_processor::base> processor_;
    ddwaf::object_limits limits_;
    data_source source_;
    bool mutable_;
};

} // namespace ddwaf
