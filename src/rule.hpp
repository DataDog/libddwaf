// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

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
              std::shared_ptr<rule_processor::base>&& processor,
              ddwaf::object_limits limits = ddwaf::object_limits(),
              data_source source = data_source::values):
        targets_(std::move(targets)),
        transformers_(std::move(transformers)),
        processor_(std::move(processor)),
        limits_(limits),
        source_(source) {}

    condition(condition&&) = default;
    condition& operator=(condition&&) = default;

    condition(const condition&) = delete;
    condition& operator=(const condition&) = delete;

    std::optional<event::match> match(const object_store& store,
        const ddwaf::manifest &manifest, bool run_on_new,
        ddwaf::timer& deadline) const;

    void reset_processor(std::shared_ptr<rule_processor::base> &proc) {
        std::atomic_store(&processor_, proc);
    }
protected:
    std::optional<event::match> match_object(const ddwaf_object* object) const;

    template <typename T>
    std::optional<event::match> match_target(T &it, ddwaf::timer& deadline) const;

    friend class rule;

    std::vector<ddwaf::manifest::target_type> targets_;
    std::vector<PW_TRANSFORM_ID> transformers_;
    std::shared_ptr<rule_processor::base> processor_;
    ddwaf::object_limits limits_;
    data_source source_;
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

struct ruleset
{
    ddwaf::manifest manifest;
    ddwaf::rule_vector rules;
    ddwaf::collection_map collections;
};

}
