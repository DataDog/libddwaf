// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <log.hpp>
#include <utils.h>
#include <string_view>
#include <memory>
#include <type_traits>
#include <parameter.hpp>
#include <rule.hpp>
#include <parser/rule_data_parser.hpp>

namespace ddwaf::rule_data {

class dispatcher
{
protected:
    class type_dispatcher_base {
    public:
        virtual ~type_dispatcher_base() = default;
        virtual void dispatch(std::string_view type, ddwaf::parameter &data) = 0;
    };

    template<typename RuleDataType>
    class type_dispatcher : public type_dispatcher_base {
    public:
        using constructor_wrapper_function =
            std::function<std::unique_ptr<rule_processor::base>(const RuleDataType&)>;

        type_dispatcher() = default;
        ~type_dispatcher() override = default;

        void insert(constructor_wrapper_function &&fn, condition& cond) {
            functions_.emplace_back(std::move(fn), cond);
        }

        void dispatch(std::string_view type, ddwaf::parameter &data) override {
            auto converted_data = parser::parse_rule_data<RuleDataType>(type, data);
            for (auto &[fn, cond] : functions_) {
                auto processor = fn(converted_data);
                if (processor) {
                    cond.reset_processor(std::move(processor));
                }
            }
        }

    protected:
        std::vector<std::pair<constructor_wrapper_function, condition&>> functions_;
    };

public:
    dispatcher() = default;
    ~dispatcher() = default;

    dispatcher(const dispatcher&) = delete;
    dispatcher& operator=(const dispatcher&) = delete;

    dispatcher(dispatcher&&) = default;
    dispatcher& operator=(dispatcher&&) = default;

    template<typename RuleProcessorType,
        typename = std::enable_if_t<std::conjunction_v<
            std::is_base_of<rule_processor::base, std::remove_cv_t<std::decay_t<RuleProcessorType>>>,
            std::negation<std::is_same<rule_processor::base,
                std::remove_cv_t<std::decay_t<RuleProcessorType>>>>>>>
    void register_condition(const std::string &id, condition &cond)
    {
        using rule_data_type = typename RuleProcessorType::rule_data_type;
        auto it = type_dispatchers_.find(id);
        if (it == type_dispatchers_.end()) {
            auto [new_it, res] = type_dispatchers_.emplace(id,
                std::make_unique<type_dispatcher<rule_data_type>>());
            it = new_it;
        }

        auto &td = dynamic_cast<type_dispatcher<rule_data_type>&>(*it->second.get());

        td.insert([](const rule_data_type & data) {
            return std::make_unique<RuleProcessorType>(data);
        }, cond);
    }

    void dispatch(const std::string &id, std::string_view type, parameter &data) {
        auto it = type_dispatchers_.find(id);
        if (it == type_dispatchers_.end()) {
            DDWAF_ERROR("Dispatcher not found for id '%s'", id.c_str());
            return;
        }

        it->second->dispatch(type, data);
    }

    void dispatch(parameter::vector &input) {
        for (ddwaf::parameter object : input) {
            std::string id;
            try {
                ddwaf::parameter::map entry = object;

                id = parser::at<std::string>(entry, "id");
                auto type = parser::at<std::string_view>(entry, "type");

                DDWAF_DEBUG("Updating rules with id '%s' and type '%s'",
                    id.c_str(), type.data());

                auto data = parser::at<parameter>(entry, "data");
                dispatch(id, type, data);
            } catch (const ddwaf::exception &e) {
                DDWAF_ERROR("Failed to parse data id '%s': %s",
                    (!id.empty() ? id.c_str() : "(unknown)"), e.what());

            }
        }
    }
protected:
    std::unordered_map<std::string,
        std::unique_ptr<type_dispatcher_base>> type_dispatchers_;
};

class dispatcher_builder {
public:
    void insert(std::string_view id, std::size_t rule_idx, std::size_t cond_idx)
    {
        entries_.emplace_back(
            dispatcher_entry{std::string(id), rule_idx, cond_idx});
    }

    dispatcher build(ddwaf::rule_vector &rules);
protected:
    struct dispatcher_entry {
        std::string id;
        std::size_t rule_idx;
        std::size_t cond_idx;
    };

    std::vector<dispatcher_entry> entries_;
};
}
