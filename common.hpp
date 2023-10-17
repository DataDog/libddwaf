// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "context_allocator.hpp"
#include "ddwaf.h"

namespace ddwaf::exclusion {

enum class filter_mode : uint8_t { none = 0, monitor = 1, bypass = 2 };

struct object_set {
    memory::unordered_set<const ddwaf_object *> persistent;
    std::unordered_set<const ddwaf_object *> ephemeral;

    bool empty() const { return persistent.empty() && ephemeral.empty(); }
    std::size_t size() const { return persistent.size() + ephemeral.size(); }
    void add_from(const object_set &objects)
    {
        persistent.insert(objects.persistent.begin(), objects.persistent.end());
        ephemeral.insert(objects.ephemeral.begin(), objects.ephemeral.end());
    }
    bool contains(const ddwaf_object *obj) const
    {
        return persistent.contains(obj) || ephemeral.contains(obj);
    }
};

class rule;

/*struct rule_policy {*/
    /*struct object_set {*/
        /*memory::unordered_set<const ddwaf_object *> &persistent;*/
        /*std::unordered_set<const ddwaf_object *> &ephemeral;*/

        /*[[nodiscard]] bool empty() const { return persistent.empty() && ephemeral.empty(); }*/
        /*[[nodiscard]] std::size_t size() const { return persistent.size() + ephemeral.size(); }*/
        /*void add_from(const object_set &objects)*/
        /*{*/
            /*persistent.insert(objects.persistent.begin(), objects.persistent.end());*/
            /*ephemeral.insert(objects.ephemeral.begin(), objects.ephemeral.end());*/
        /*}*/
        /*[[nodiscard]] bool contains(const ddwaf_object *obj) const*/
        /*{*/
            /*return persistent.contains(obj) || ephemeral.contains(obj);*/
        /*}*/
    /*};*/

    /*filter_mode mode;*/
    /*object_set objects;*/
/*};*/


struct context_policy {
    struct rule_policy {
        filter_mode mode{filter_mode::none};
        std::unordered_set<const ddwaf_object *> objects;
    };

    void set_filter_mode(const std::unordered_set<rule *> & rules, filter_mode mode, bool ephemeral_)
    {
        std::unordered_map<rule *, rule_policy> &container = ephemeral_ ? ephemeral : persistent;
        for (auto *rule : rules) {
            auto policy = container[rule];

            // Bypass has precedence over monitor
            if (policy.mode < mode) {
                policy.mode = mode;
            }
        }
    }

    void set_objects(const std::unordered_set<rule *> & rules, object_set &objects, bool ephemeral_)
    {
        if (ephemeral_ || !objects.ephemeral.empty()) {
            for (auto *rule : rules) {
                auto policy = ephemeral[rule];

                if (policy.mode == filter_mode::bypass) {
                    continue;
                }

                if (ephemeral_) {
                    for (const auto *object : objects.persistent) {
                        policy.objects.emplace(object);
                    }
                }

                for (const auto *object : objects.ephemeral) {
                    policy.objects.emplace(object);
                }
            }
            return ;
        } 


        if (!ephemeral_ && !objects.persistent.empty()) {
            for (auto *rule : rules) {
                auto policy = persistent[rule];

                if (policy.mode == filter_mode::bypass) {
                    continue;
                }

                for (const auto *object : objects.persistent) {
                    policy.objects.emplace(object);
                }
            }
        }
    }

    std::unordered_map<rule *, rule_policy> persistent;
    std::unordered_map<rule *, rule_policy> ephemeral;
};

} // namespace ddwaf::exclusion
