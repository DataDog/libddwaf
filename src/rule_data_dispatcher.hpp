// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <utils.h>
#include <string_view>
#include <memory>
#include <type_traits>
#include <parameter.hpp>
#include <rule.hpp>

namespace ddwaf::rule_data {

class dispatcher
{
protected:
    class type_dispatcher_base {
    public:
        virtual ~type_dispatcher_base() = default;
        virtual void dispatch(const ddwaf::parameter &data) = 0;
    };

    template<typename T>
    class type_dispatcher : public type_dispatcher_base {
    public:
        using function_type = std::function<std::shared_ptr<rule_processor::base>(const T&)>;

        type_dispatcher() = default;
        ~type_dispatcher() override = default;

        void insert(function_type &&fn, condition& cond) {
            functions_.emplace_back(std::move(fn), cond);
        }

        virtual void dispatch(const ddwaf::parameter &data) {
            auto converted_data = T(data);
            for (auto &[fn, cond] : functions_) {
                auto processor = fn(converted_data);
                if (processor) {
                    cond.reset_processor(processor);
                }
            }
        }

    protected:
        std::vector<std::pair<function_type, condition&>> functions_;
    };

public:
    dispatcher() = default;
    ~dispatcher() = default;

    dispatcher(const dispatcher&) = delete;
    dispatcher& operator=(const dispatcher&) = delete;

    dispatcher(dispatcher&&) = default;
    dispatcher& operator=(dispatcher&&) = default;


    template<typename T,
        typename = std::enable_if_t<std::conjunction_v<
            std::is_base_of<rule_processor::base, std::remove_cv_t<std::decay_t<T>>>,
            std::negation<std::is_same<rule_processor::base,
                std::remove_cv_t<std::decay_t<T>>>>>>>
    void register_condition(const std::string &id, condition &cond)
    {
        using rule_data_type = typename T::rule_data_type;
        auto it = type_dispatchers_.find(id);
        if (it == type_dispatchers_.end()) {
            auto [new_it, res] = type_dispatchers_.emplace(id,
                std::make_unique<type_dispatcher<rule_data_type>>());
            it = new_it;
        }

        auto &td = dynamic_cast<type_dispatcher<rule_data_type>>(*it->second);

        td.insert([](const rule_data_type & data) {
            return std::make_shared<T>(data);
        }, cond);
    }

    // TODO: Return a known result or throw
    void dispatch(const std::string &id, ddwaf_object *data) {
        auto it = type_dispatchers_.find(id);
        if (it == type_dispatchers_.end()) {
            return;
        }

        it->second->dispatch(*data);
    }

protected:
    std::unordered_map<std::string,
        std::unique_ptr<type_dispatcher_base>> type_dispatchers_;
};

class dispatcher_builder {
public:
    void insert(std::string_view id, std::string_view op_name,
        std::size_t rule_idx, std::size_t cond_idx)
    {
        entries_.emplace_back(dispatcher_entry{id, op_name, rule_idx, cond_idx});
    }

    dispatcher build(ddwaf::rule_vector &rules);
protected:
    struct dispatcher_entry {
        std::string_view id;
        std::string_view op_name;
        std::size_t rule_idx;
        std::size_t cond_idx;
    };

    std::vector<dispatcher_entry> entries_;
};
}
