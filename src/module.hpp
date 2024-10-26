// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "event.hpp"
#include "exclusion/rule_filter.hpp"
#include "rule.hpp"

namespace ddwaf {

enum class collection_type : uint8_t { none = 0, regular = 1, priority = 2 };

struct collection_cache {
    collection_type type{collection_type::none};
    bool ephemeral{false};
};

struct module_cache {
    memory::unordered_map<std::string_view, collection_cache> collections;
    memory::vector<rule::cache_type> rules;
};

class collection_module {
public:
    using cache_type = module_cache;
    using iterator = std::vector<std::shared_ptr<rule>>::iterator;
    using const_iterator = std::vector<std::shared_ptr<rule>>::const_iterator;

    collection_module() = default;
    ~collection_module() = default;
    collection_module(const collection_module &) = default;
    collection_module(collection_module &&) noexcept = default;
    collection_module &operator=(const collection_module &) = default;
    collection_module &operator=(collection_module &&) noexcept = default;

    void eval(std::vector<event> &events, object_store &store, module_cache &cache,
        const exclusion::context_policy &exclusion,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const;

    [[nodiscard]] bool empty() const noexcept { return rules_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return rules_.size(); }

    iterator begin() { return rules_.begin(); }
    [[nodiscard]] const_iterator begin() const { return rules_.begin(); }

    iterator end() { return rules_.end(); }
    [[nodiscard]] const_iterator end() const { return rules_.end(); }

protected:
    struct rule_collection {
        std::string_view name;
        collection_type type;
        std::size_t start;
        std::size_t end;
    };

    collection_module(
        std::vector<rule_collection> &&collections, std::vector<std::shared_ptr<rule>> &&rules)
        : collections_(std::move(collections)), rules_(std::move(rules))
    {}

    std::vector<rule_collection> collections_;
    std::vector<std::shared_ptr<rule>> rules_;

    friend class collection_module_builder;
};

class collection_module_builder {
public:
    void insert(const std::shared_ptr<rule> &rule) { rules_.emplace_back(rule); }

    collection_module build()
    {
        std::sort(rules_.begin(), rules_.end(), [](const auto &left, const auto &right) {
            auto ltype = left->get_collection();
            auto rtype = right->get_collection();

            auto res = ltype.compare(rtype);

            return res < 0 ||
                   (res == 0 && ((!left->get_actions().empty() && right->get_actions().empty()) ||
                                    (left->get_actions().empty() == right->get_actions().empty() &&
                                        left->get_source() > right->get_source())));
        });

        // Compute the ranges of each collection
        std::vector<collection_module::rule_collection> collections;
        if (!rules_.empty()) {
            auto current_type = rules_[0]->get_collection();
            collections.emplace_back(current_type,
                rules_[0]->get_actions().empty() ? collection_type::regular
                                                 : collection_type::priority,
                0, rules_.size());

            for (std::size_t i = 1; i < rules_.size(); ++i) {
                auto this_type = rules_[i]->get_collection();
                if (this_type != current_type) {
                    collections.back().end = i;

                    current_type = this_type;
                    collections.emplace_back(current_type,
                        rules_[0]->get_actions().empty() ? collection_type::regular
                                                         : collection_type::priority,
                        i, rules_.size());
                }
            }
        }

        return {std::move(collections), std::move(rules_)};
    }

protected:
    // Keep track of the first index of the collection
    std::unordered_map<std::string_view, std::size_t> collection_start_;
    std::vector<std::shared_ptr<rule>> rules_;
};
} // namespace ddwaf
