// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <rule_processor/base.hpp>
#include <iterator.hpp>
#include <manifest.hpp>
#include <event.hpp>
#include <object_store.hpp>
#include <PWTransformer.h>
#include <clock.hpp>

namespace ddwaf
{

class rule;

// TODO Move condition into rule
class condition
{
public:
    enum class data_source : uint8_t {
        values,
        keys
    };

    condition(std::vector<ddwaf::manifest::target_type>&& targets,
              std::vector<PW_TRANSFORM_ID>&& transformers,
              std::unique_ptr<rule_processor::base> processor,
              ddwaf::object_limits limits = ddwaf::object_limits(),
              data_source source = data_source::values,
              bool is_mutable = false):
        targets_(std::move(targets)),
        transformers_(std::move(transformers)),
        processor_(processor.release()),
        limits_(limits),
        source_(source),
        mutable_(is_mutable) {}

    // This constructor should *not* be used after the rule has been put into
    // operation, for processor_ contains an atomic variable
    condition(condition&& oth) : targets_(std::move(oth.targets_)),
                                 transformers_(std::move(oth.transformers_)),
                                 processor_(oth.processor_.load()),
                                 limits_(oth.limits_),
                                 source_(oth.source_),
                                 mutable_(oth.mutable_)
    {
        oth.processor_.store(nullptr);
    }
    condition& operator=(condition&&) = delete;

    condition(const condition&) = delete;
    condition& operator=(const condition&) = delete;

    ~condition() {
        delete processor_.load(std::memory_order_relaxed).get();
    }

    std::optional<event::match> match(const object_store& store,
        const ddwaf::manifest &manifest, bool run_on_new,
        ddwaf::timer& deadline) const;

    std::string_view processor_name() {
        if (!mutable_) {
            return processor_.load(std::memory_order_relaxed)->name();
        }

        guard_ptr gptr;
        gptr.acquire(processor_, std::memory_order_acquire);
        return gptr->name();
    }

    void reset_processor(std::unique_ptr<rule_processor::base> proc) {
        if (!mutable_) {
            throw std::runtime_error("Attempting to mutate an immutable "
                                     "condition with processor "
                                     + std::string(processor_.load()->name()));
        }

        marked_ptr new_proc = proc.release();

        while (true)
        {
            guard_ptr guard;
            marked_ptr cur_proc;
            guard.acquire(processor_, std::memory_order_relaxed);
            cur_proc = guard.get();
            if (processor_.compare_exchange_strong(
                    cur_proc, new_proc,
                    std::memory_order_release, std::memory_order_relaxed))
            {
                guard.reclaim();
                break;
            }
            guard.reset();
            continue;
        }
    }
protected:
    using Reclaimer = rule_processor::Reclaimer;
    using concurrent_ptr = Reclaimer::concurrent_ptr<rule_processor::base>;
    using marked_ptr = concurrent_ptr::marked_ptr;
    using guard_ptr = concurrent_ptr::guard_ptr;

    std::optional<event::match> match_object(const ddwaf_object* object) const;

    template <typename T>
    std::optional<event::match> match_target(T &it, ddwaf::timer& deadline) const;

    friend class rule;

    std::vector<ddwaf::manifest::target_type> targets_;
    std::vector<PW_TRANSFORM_ID> transformers_;
    concurrent_ptr processor_;
    ddwaf::object_limits limits_;
    data_source source_;
    bool mutable_;
};

class rule
{
public:
    using index_type = uint32_t;

    // TODO: make fields protected, add getters, follow conventions, add cache
    //       move condition matching from context.
    rule(index_type index_, std::string &&id_, std::string &&name_,
      std::string &&type_, std::string &&category_,
      std::vector<condition> &&conditions_,
      std::vector<std::string> &&actions_ = {});

    rule(const rule&) = delete;
    rule& operator=(const rule&) = delete;

    rule(rule&&) = default;
    rule& operator=(rule&&) = default;

    ~rule() = default;

    bool has_new_targets(const object_store &store) const;

    std::optional<event> match(const object_store& store,
        const ddwaf::manifest &manifest, bool run_on_new,
        ddwaf::timer& deadline) const;

    index_type index;
    std::string id;
    std::string name;
    std::string type;
    std::string category;
    std::vector<condition> conditions;
    std::unordered_set<ddwaf::manifest::target_type> targets;
    std::vector<std::string> actions;
};

using rule_map        = std::unordered_map<rule::index_type, rule>;
using rule_vector     = std::vector<rule>;
using rule_ref_vector = std::vector<std::reference_wrapper<rule>>;
using collection_map  = std::unordered_map<std::string, rule_ref_vector>;

}
