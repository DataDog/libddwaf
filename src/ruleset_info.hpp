// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "configuration/common/parser_exception.hpp"
#include "object.hpp"
#include "utils.hpp"

namespace ddwaf {

inline std::string index_to_id(unsigned idx) { return "index:" + to_string(idx); }

enum class ruleset_info_state : uint8_t { empty, invalid, valid };

class ruleset_info {
public:
    class section_info {
    public:
        section_info()
            : loaded_(owned_object::make_array(0, memory::get_default_resource())),
              failed_(owned_object::make_array(0, memory::get_default_resource())),
              skipped_(owned_object::make_array(0, memory::get_default_resource())),
              errors_(owned_object::make_map(0, memory::get_default_resource())),
              warnings_(owned_object::make_map(0, memory::get_default_resource()))
        {}

        ~section_info() = default;

        section_info(const section_info &) = delete;
        section_info(section_info &&) noexcept = default;
        section_info &operator=(const section_info &) = delete;
        section_info &operator=(section_info &&) noexcept = delete;

        void set_error(std::string_view error) { error_ = error; }
        void add_loaded(std::string_view id);
        void add_failed(std::string_view id, parser_error_severity sev, std::string_view error);
        void add_skipped(std::string_view id);

        void add_loaded(unsigned index)
        {
            auto id_str = index_to_id(index);
            add_loaded(id_str);
        }
        void add_skipped(unsigned index)
        {
            auto id_str = index_to_id(index);
            add_skipped(id_str);
        }

        void add_failed(unsigned index, parser_error_severity sev, std::string_view error)
        {
            auto id_str = index_to_id(index);
            add_failed(id_str, sev, error);
        }
        void add_failed(
            unsigned index, std::string_view id, parser_error_severity sev, std::string_view error)
        {
            if (id.empty()) {
                auto id_str = index_to_id(index);
                add_failed(id_str, sev, error);
            } else {
                add_failed(id, sev, error);
            }
        }
        // This matcher effectively moves the contents
        owned_object to_object()
        {
            auto output = owned_object::make_map(5, memory::get_default_resource());
            if (!error_.empty()) {
                output.emplace("error", error_);
                error_.clear();
            } else {
                output.emplace("loaded", std::move(loaded_));
                output.emplace("failed", std::move(failed_));
                output.emplace("skipped", std::move(skipped_));
                output.emplace("errors", std::move(errors_));
                output.emplace("warnings", std::move(warnings_));

                error_obj_cache_.clear();
                warning_obj_cache_.clear();
            }
            return output;
        }

        [[nodiscard]] ruleset_info_state state() const noexcept
        {
            //  The section is valid if there are no errors and
            if (error_.empty() && !loaded_.empty()) {
                return ruleset_info_state::valid;
            }

            if (!error_.empty() || !failed_.empty()) {
                return ruleset_info_state::invalid;
            }

            return ruleset_info_state::empty;
        }

    protected:
        std::string error_;
        /** Array of loaded elements */
        owned_object loaded_;
        /** Array of failed elements */
        owned_object failed_;
        /** Array of skipped elements */
        owned_object skipped_;
        /** Map from an error string to an array of all the ids for which
         *  that error was raised. {error: [ids]} **/
        owned_object errors_;
        std::map<std::string_view, uint64_t> error_obj_cache_;
        /** Map from an warning string to an array of all the ids for which
         *  that warning was raised. {warning: [ids]} **/
        owned_object warnings_;
        std::map<std::string_view, uint64_t> warning_obj_cache_;
    };

    ruleset_info() = default;
    ~ruleset_info() = default;

    ruleset_info(const ruleset_info &) = delete;
    ruleset_info(ruleset_info &&) noexcept = default;
    ruleset_info &operator=(const ruleset_info &) = delete;
    ruleset_info &operator=(ruleset_info &&) noexcept = delete;

    section_info &add_section(std::string_view section)
    {
        auto [it, res] = sections_.emplace(section, section_info{});
        return it->second;
    }

    void set_ruleset_version(std::string_view version) { ruleset_version_ = version; }

    // This method effectively moves the contents
    owned_object to_object()
    {
        auto output = owned_object::make_map(0, memory::get_default_resource());
        if (!error_.empty()) {
            output.emplace("error", error_);
            error_.clear();
        } else {
            for (auto &[name, section] : sections_) { output.emplace(name, section.to_object()); }
            sections_.clear();

            if (!ruleset_version_.empty()) {
                output.emplace("ruleset_version", ruleset_version_);
                ruleset_version_.clear();
            }
        }
        return output;
    }

    void set_error(std::string error) { error_ = std::move(error); }

    [[nodiscard]] ruleset_info_state state() const noexcept
    {
        if (!error_.empty()) {
            return ruleset_info_state::invalid;
        }

        auto final_state = ruleset_info_state::empty;
        for (const auto &[_, section] : sections_) {
            switch (section.state()) {
            case ruleset_info_state::valid:
                return ruleset_info_state::valid;
            case ruleset_info_state::invalid:
                final_state = ruleset_info_state::invalid;
                break;
            default:
                break;
            }
        }
        return final_state;
    }

protected:
    std::string ruleset_version_;
    std::string error_;
    std::map<std::string, section_info, std::less<>> sections_;
};

} // namespace ddwaf
