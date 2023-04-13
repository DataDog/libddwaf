// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "utils.hpp"
#include <ddwaf.h>
#include <map>
#include <string>
#include <string_view>

namespace ddwaf {

class base_ruleset_info {
public:
    class base_section_info {
    public:
        base_section_info() = default;
        virtual ~base_section_info() = default;
        base_section_info(const base_section_info &) = default;
        base_section_info(base_section_info &&) noexcept = default;
        base_section_info &operator=(const base_section_info &) = default;
        base_section_info &operator=(base_section_info &&) noexcept = default;

        virtual void add_loaded(std::string_view id) = 0;
        virtual void add_failed(std::string_view id) = 0;
        virtual void add_failed(std::string_view id, std::string_view error) = 0;
    };

    base_ruleset_info() = default;
    virtual ~base_ruleset_info() = default;
    base_ruleset_info(const base_ruleset_info &) = default;
    base_ruleset_info(base_ruleset_info &&) noexcept = default;
    base_ruleset_info &operator=(const base_ruleset_info &) = default;
    base_ruleset_info &operator=(base_ruleset_info &&) noexcept = default;

    virtual base_section_info &add_section(std::string_view section) = 0;
    virtual void set_ruleset_version(std::string_view version) = 0;
};

class null_ruleset_info : public base_ruleset_info {
public:
    class null_section_info : public base_ruleset_info::base_section_info {
    public:
        null_section_info() = default;
        ~null_section_info() override = default;
        null_section_info(const null_section_info &) = default;
        null_section_info(null_section_info &&) noexcept = default;
        null_section_info &operator=(const null_section_info &) = default;
        null_section_info &operator=(null_section_info &&) noexcept = default;

        void add_loaded(std::string_view /*id*/) override {}
        void add_failed(std::string_view /*id*/) override {}
        void add_failed(std::string_view /*id*/, std::string_view /*error*/) override {}
    };

    null_ruleset_info() = default;
    ~null_ruleset_info() override = default;
    null_ruleset_info(const null_ruleset_info &) = default;
    null_ruleset_info(null_ruleset_info &&) noexcept = default;
    null_ruleset_info &operator=(const null_ruleset_info &) = default;
    null_ruleset_info &operator=(null_ruleset_info &&) noexcept = default;

    base_section_info &add_section(std::string_view /*section*/) override
    {
        static null_section_info section;
        return section;
    }

    void set_ruleset_version(std::string_view /*version*/) override{};
};

class ruleset_info : public base_ruleset_info {
public:
    class section_info : public base_ruleset_info::base_section_info {
    public:
        section_info()
        {
            ddwaf_object_array(&loaded);
            ddwaf_object_array(&failed);
            ddwaf_object_map(&errors);
        }

        ~section_info() override = default;
        section_info(const section_info &) = default;
        section_info(section_info &&) noexcept = default;
        section_info &operator=(const section_info &) = default;
        section_info &operator=(section_info &&) noexcept = default;

        void add_loaded(std::string_view id) override;
        void add_failed(std::string_view id) override { return add_failed(id, ""); }
        void add_failed(std::string_view id, std::string_view error) override;

        void to_object(ddwaf_object &output)
        {
            ddwaf_object_map(&output);
            ddwaf_object_map_add(&output, "loaded", &loaded);
            ddwaf_object_map_add(&output, "failed", &failed);
            ddwaf_object_map_add(&output, "errors", &errors);
        }

    protected:
        /** Array of loaded elements */
        ddwaf_object loaded{};
        /** Array of failed elements */
        ddwaf_object failed{};
        /** Map from an error string to an array of all the ids for which
         *  that error was raised. {error: [ids]} **/
        ddwaf_object errors{};
        std::map<std::string_view, uint64_t> error_obj_cache;
    };

    explicit ruleset_info(ddwaf_object &root) : root_(root) { ddwaf_object_map(&root_); }

    ~ruleset_info() override
    {
        for (auto &[name, section] : sections_) {
            ddwaf_object section_object;
            section.to_object(section_object);

            ddwaf_object_map_addl(&root_, name.c_str(), name.length(), &section_object);
        }
    }

    ruleset_info(const ruleset_info &) = default;
    ruleset_info(ruleset_info &&) noexcept = default;
    ruleset_info &operator=(const ruleset_info &) = delete;
    ruleset_info &operator=(ruleset_info &&) noexcept = delete;

    base_section_info &add_section(std::string_view section) override
    {
        auto [it, res] = sections_.emplace(section, section_info{});
        return it->second;
    }

    void set_ruleset_version(std::string_view version) override
    {
        ddwaf_object version_obj;
        ddwaf_object_stringl(&version_obj, version.data(), version.size());
        ddwaf_object_map_add(&root_, "ruleset_version", &version_obj);
    }

protected:
    ddwaf_object &root_;
    std::map<std::string, section_info, std::less<>> sections_;
};

} // namespace ddwaf
