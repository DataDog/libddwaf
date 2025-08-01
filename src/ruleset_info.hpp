// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <map>
#include <string>
#include <string_view>

#include "configuration/common/parser_exception.hpp"
#include "ddwaf.h"
#include "utils.hpp"

namespace ddwaf {

inline std::string index_to_id(unsigned idx) { return "index:" + to_string<std::string>(idx); }

enum class ruleset_info_state : uint8_t { empty, invalid, valid };

class ruleset_info {
public:
    class section_info {
    public:
        section_info()
        {
            ddwaf_object_array(&loaded_);
            ddwaf_object_array(&failed_);
            ddwaf_object_array(&skipped_);
            ddwaf_object_map(&errors_);
            ddwaf_object_map(&warnings_);
        }

        ~section_info()
        {
            ddwaf_object_free(&loaded_);
            ddwaf_object_free(&failed_);
            ddwaf_object_free(&skipped_);
            ddwaf_object_free(&errors_);
            ddwaf_object_free(&warnings_);
        }

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
        void to_object(ddwaf_object &output)
        {
            ddwaf_object_map(&output);
            if (!error_.empty()) {
                ddwaf_object error_str;
                ddwaf_object_stringl(&error_str, error_.c_str(), error_.size());
                ddwaf_object_map_add(&output, "error", &error_str);
                error_.clear();
            } else {
                ddwaf_object_map_add(&output, "loaded", &loaded_);
                ddwaf_object_map_add(&output, "failed", &failed_);
                ddwaf_object_map_add(&output, "skipped", &skipped_);
                ddwaf_object_map_add(&output, "errors", &errors_);
                ddwaf_object_map_add(&output, "warnings", &warnings_);

                ddwaf_object_invalid(&loaded_);
                ddwaf_object_invalid(&failed_);
                ddwaf_object_invalid(&skipped_);

                ddwaf_object_invalid(&errors_);
                error_obj_cache_.clear();

                ddwaf_object_invalid(&warnings_);
                warning_obj_cache_.clear();
            }
        }

        [[nodiscard]] ruleset_info_state state() const noexcept
        {
            //  The section is valid if there are no errors and
            if (error_.empty() && ddwaf_object_size(&loaded_) > 0) {
                return ruleset_info_state::valid;
            }

            if (!error_.empty() || ddwaf_object_size(&failed_) > 0) {
                return ruleset_info_state::invalid;
            }

            return ruleset_info_state::empty;
        }

    protected:
        std::string error_;
        /** Array of loaded elements */
        ddwaf_object loaded_{};
        /** Array of failed elements */
        ddwaf_object failed_{};
        /** Array of skipped elements */
        ddwaf_object skipped_{};
        /** Map from an error string to an array of all the ids for which
         *  that error was raised. {error: [ids]} **/
        ddwaf_object errors_{};
        std::map<std::string_view, uint64_t> error_obj_cache_;
        /** Map from an warning string to an array of all the ids for which
         *  that warning was raised. {warning: [ids]} **/
        ddwaf_object warnings_{};
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

    // This matcher effectively moves the contents
    void to_object(ddwaf_object &output)
    {
        ddwaf_object_map(&output);
        if (!error_.empty()) {
            ddwaf_object error_object;
            ddwaf_object_stringl(&error_object, error_.c_str(), error_.size());
            ddwaf_object_map_add(&output, "error", &error_object);
            error_.clear();
        } else {
            for (auto &[name, section] : sections_) {
                ddwaf_object section_object;
                section.to_object(section_object);

                ddwaf_object_map_addl(&output, name.c_str(), name.length(), &section_object);
            }
            sections_.clear();

            if (!ruleset_version_.empty()) {
                ddwaf_object version_object;
                ddwaf_object_stringl(
                    &version_object, ruleset_version_.c_str(), ruleset_version_.size());
                ddwaf_object_map_add(&output, "ruleset_version", &version_object);
                ruleset_version_.clear();
            }
        }
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
