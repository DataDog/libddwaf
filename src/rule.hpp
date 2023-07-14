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

#include <PWTransformer.h>
#include <clock.hpp>
#include <condition.hpp>
#include <event.hpp>
#include <iterator.hpp>
#include <object_store.hpp>
#include <rule_processor/base.hpp>

namespace ddwaf {

class rule {
public:
    using ptr = std::shared_ptr<rule>;

    enum class source_type : uint8_t { base = 1, user = 2 };

    struct cache_type {
        bool result{false};
        memory::vector<event::match> matches;
        std::optional<std::vector<condition::ptr>::const_iterator> last_cond{};
    };

    rule(std::string id, std::string name, absl::flat_hash_map<std::string, std::string> tags,
        std::vector<condition::ptr> conditions, std::vector<std::string> actions = {},
        bool enabled = true, source_type source = source_type::base)
        : enabled_(enabled), source_(source), id_(std::move(id)), name_(std::move(name)),
          tags_(std::move(tags)), conditions_(std::move(conditions)), actions_(std::move(actions))
    {}

    rule(const rule &) = delete;
    rule &operator=(const rule &) = delete;

    rule(rule &&rhs) noexcept
        : enabled_(rhs.enabled_), source_(rhs.source_), id_(std::move(rhs.id_)),
          name_(std::move(rhs.name_)), tags_(std::move(rhs.tags_)),
          conditions_(std::move(rhs.conditions_)), actions_(std::move(rhs.actions_))
    {}

    rule &operator=(rule &&rhs) noexcept
    {
        enabled_ = rhs.enabled_;
        source_ = rhs.source_;
        id_ = std::move(rhs.id_);
        name_ = std::move(rhs.name_);
        tags_ = std::move(rhs.tags_);
        conditions_ = std::move(rhs.conditions_);
        actions_ = std::move(rhs.actions_);
        return *this;
    }

    ~rule() = default;

    std::optional<event> match(const object_store &store, cache_type &cache,
        const absl::flat_hash_set<const ddwaf_object *> &objects_excluded,
        const absl::flat_hash_map<std::string, rule_processor::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const;

    [[nodiscard]] bool is_enabled() const { return enabled_; }
    void toggle(bool value) { enabled_ = value; }

    source_type get_source() const { return source_; }
    const std::string &get_id() const { return id_; }
    const std::string &get_name() const { return name_; }

    std::string_view get_tag(const std::string &tag) const
    {
        auto it = tags_.find(tag);
        return it == tags_.end() ? std::string_view() : it->second;
    }

    const absl::flat_hash_map<std::string, std::string> &get_tags() const { return tags_; }

    const std::vector<std::string> &get_actions() const { return actions_; }

    void get_addresses(absl::flat_hash_set<std::string> &addresses) const
    {
        for (const auto &cond : conditions_) {
            for (const auto &target : cond->get_targets()) { addresses.emplace(target.name); }
        }
    }

    void set_actions(std::vector<std::string> new_actions) { actions_ = std::move(new_actions); }

protected:
    bool enabled_{true};
    source_type source_;
    std::string id_;
    std::string name_;
    absl::flat_hash_map<std::string, std::string> tags_;
    std::vector<condition::ptr> conditions_;
    std::vector<std::string> actions_;
};

} // namespace ddwaf
