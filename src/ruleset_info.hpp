// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <boost/unordered/unordered_flat_set.hpp>
#include <map>
#include <string>
#include <string_view>

#include "ddwaf.h"
#include "utils.hpp"

namespace ddwaf {

class base_ruleset_info {
public:
    class base_section_info {
    public:
        base_section_info() = default;
        virtual ~base_section_info() = default;
        base_section_info(const base_section_info &) = delete;
        base_section_info(base_section_info &&) noexcept = default;
        base_section_info &operator=(const base_section_info &) = delete;
        base_section_info &operator=(base_section_info &&) noexcept = delete;

        virtual void set_error(std::string_view error) = 0;
        virtual void add_loaded(std::string_view id) = 0;
        virtual void add_failed(std::string_view id, std::string_view error) = 0;
        virtual void add_required_address(std::string_view address) = 0;
        virtual void add_optional_address(std::string_view address) = 0;
    };

    base_ruleset_info() = default;
    virtual ~base_ruleset_info() = default;
    base_ruleset_info(const base_ruleset_info &) = delete;
    base_ruleset_info(base_ruleset_info &&) noexcept = default;
    base_ruleset_info &operator=(const base_ruleset_info &) = delete;
    base_ruleset_info &operator=(base_ruleset_info &&) noexcept = delete;

    virtual base_section_info &add_section(std::string_view section) = 0;
    virtual void set_ruleset_version(std::string_view version) = 0;

    virtual void to_object(ddwaf_object &output) = 0;
};

class null_ruleset_info : public base_ruleset_info {
public:
    class section_info : public base_ruleset_info::base_section_info {
    public:
        section_info() = default;
        ~section_info() override = default;
        section_info(const section_info &) = delete;
        section_info(section_info &&) noexcept = default;
        section_info &operator=(const section_info &) = delete;
        section_info &operator=(section_info &&) noexcept = delete;

        void set_error(std::string_view /*error*/) override {}
        void add_loaded(std::string_view /*id*/) override {}
        void add_failed(std::string_view /*id*/, std::string_view /*error*/) override {}
        void add_required_address(std::string_view /*address*/) override {}
        void add_optional_address(std::string_view /*address*/) override {}
    };

    null_ruleset_info() = default;
    ~null_ruleset_info() override = default;
    null_ruleset_info(const null_ruleset_info &) = delete;
    null_ruleset_info(null_ruleset_info &&) noexcept = default;
    null_ruleset_info &operator=(const null_ruleset_info &) = delete;
    null_ruleset_info &operator=(null_ruleset_info &&) noexcept = delete;

    base_section_info &add_section(std::string_view /*section*/) override
    {
        static section_info section;
        return section;
    }

    void set_ruleset_version(std::string_view /*version*/) override{};

    void to_object(ddwaf_object & /*output*/) override{};
};

class ruleset_info : public base_ruleset_info {
public:
    class section_info : public base_ruleset_info::base_section_info {
    public:
        section_info()
        {
            ddwaf_object_array(&loaded_);
            ddwaf_object_array(&failed_);
            ddwaf_object_map(&errors_);
            ddwaf_object_array(&required_addresses_);
            ddwaf_object_array(&optional_addresses_);
        }

        ~section_info() override
        {
            ddwaf_object_free(&loaded_);
            ddwaf_object_free(&failed_);
            ddwaf_object_free(&errors_);
            ddwaf_object_free(&required_addresses_);
            ddwaf_object_free(&optional_addresses_);
        }

        section_info(const section_info &) = delete;
        section_info(section_info &&) noexcept = default;
        section_info &operator=(const section_info &) = delete;
        section_info &operator=(section_info &&) noexcept = delete;

        void set_error(std::string_view error) override { error_ = error; }
        void add_loaded(std::string_view id) override;
        void add_failed(std::string_view id, std::string_view error) override;
        void add_required_address(std::string_view address) override;
        void add_optional_address(std::string_view address) override;

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
                ddwaf_object_map_add(&output, "errors", &errors_);

                if (!required_addresses_set_.empty() || !optional_addresses_set_.empty()) {
                    ddwaf_object addresses;
                    ddwaf_object_map(&addresses);
                    ddwaf_object_map_add(&addresses, "required", &required_addresses_);
                    ddwaf_object_map_add(&addresses, "optional", &optional_addresses_);
                    ddwaf_object_map_add(&output, "addresses", &addresses);
                }

                ddwaf_object_invalid(&loaded_);
                ddwaf_object_invalid(&failed_);

                ddwaf_object_invalid(&errors_);
                error_obj_cache_.clear();

                ddwaf_object_invalid(&required_addresses_);
                required_addresses_set_.clear();

                ddwaf_object_invalid(&optional_addresses_);
                optional_addresses_set_.clear();
            }
        }

    protected:
        std::string error_;
        /** Array of loaded elements */
        ddwaf_object loaded_{};
        /** Array of failed elements */
        ddwaf_object failed_{};
        /** Map from an error string to an array of all the ids for which
         *  that error was raised. {error: [ids]} **/
        ddwaf_object errors_{};
        std::map<std::string_view, uint64_t> error_obj_cache_;

        /** Array of required addresses **/
        ddwaf_object required_addresses_{};
        boost::unordered_flat_set<std::string_view> required_addresses_set_{};

        /** Array of optional addresses **/
        ddwaf_object optional_addresses_{};
        boost::unordered_flat_set<std::string_view> optional_addresses_set_{};
    };

    ruleset_info() = default;
    ~ruleset_info() override = default;

    ruleset_info(const ruleset_info &) = delete;
    ruleset_info(ruleset_info &&) noexcept = default;
    ruleset_info &operator=(const ruleset_info &) = delete;
    ruleset_info &operator=(ruleset_info &&) noexcept = delete;

    base_section_info &add_section(std::string_view section) override
    {
        auto [it, res] = sections_.emplace(section, section_info{});
        return it->second;
    }

    void set_ruleset_version(std::string_view version) override { ruleset_version_ = version; }

    // This matcher effectively moves the contents
    void to_object(ddwaf_object &output) override
    {
        ddwaf_object_map(&output);
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

protected:
    std::string ruleset_version_;
    std::map<std::string, section_info, std::less<>> sections_;
};

} // namespace ddwaf
