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
#include "object.hpp"
#include "utils.hpp"

namespace ddwaf {

inline std::string index_to_id(unsigned idx) { return "index:" + to_string<std::string>(idx); }

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

        virtual void add_loaded(unsigned index)
        {
            auto id_str = index_to_id(index);
            add_loaded(id_str);
        }
        virtual void add_loaded(std::string_view id) = 0;

        virtual void add_skipped(unsigned index)
        {
            auto id_str = index_to_id(index);
            add_skipped(id_str);
        }
        virtual void add_skipped(std::string_view id) = 0;

        virtual void add_failed(unsigned index, parser_error_severity sev, std::string_view error)
        {
            auto id_str = index_to_id(index);
            add_failed(id_str, sev, error);
        }
        virtual void add_failed(
            unsigned index, std::string_view id, parser_error_severity sev, std::string_view error)
        {
            if (id.empty()) {
                auto id_str = index_to_id(index);
                add_failed(id_str, sev, error);
            } else {
                add_failed(id, sev, error);
            }
        }
        virtual void add_failed(
            std::string_view id, parser_error_severity sev, std::string_view error) = 0;
    };

    base_ruleset_info() = default;
    virtual ~base_ruleset_info() = default;
    base_ruleset_info(const base_ruleset_info &) = delete;
    base_ruleset_info(base_ruleset_info &&) noexcept = default;
    base_ruleset_info &operator=(const base_ruleset_info &) = delete;
    base_ruleset_info &operator=(base_ruleset_info &&) noexcept = delete;

    virtual base_section_info &add_section(std::string_view section) = 0;
    virtual void set_ruleset_version(std::string_view version) = 0;
    virtual void set_error(std::string error) = 0;

    virtual owned_object to_object() = 0;
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
        void add_failed(std::string_view /*id*/, parser_error_severity /*sev*/,
            std::string_view /*error*/) override
        {}
        void add_skipped(std::string_view /*id*/) override {}
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
    void set_error(std::string /*error*/) override {}

    owned_object to_object() override { return {}; };
};

class ruleset_info : public base_ruleset_info {
public:
    class section_info : public base_ruleset_info::base_section_info {
    public:
        section_info()
            : loaded_(owned_object::make_array()), failed_(owned_object::make_array()),
              skipped_(owned_object::make_array()), errors_(owned_object::make_map()),
              warnings_(owned_object::make_map())
        {}

        ~section_info() override = default;

        section_info(const section_info &) = delete;
        section_info(section_info &&) noexcept = default;
        section_info &operator=(const section_info &) = delete;
        section_info &operator=(section_info &&) noexcept = delete;

        void set_error(std::string_view error) override { error_ = error; }
        void add_loaded(std::string_view id) override;
        void add_failed(
            std::string_view id, parser_error_severity sev, std::string_view error) override;
        void add_skipped(std::string_view id) override;

        // This matcher effectively moves the contents
        owned_object to_object()
        {
            auto output = owned_object::make_map();
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
    owned_object to_object() override
    {
        auto output = owned_object::make_map();
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

    void set_error(std::string error) override { error_ = std::move(error); }

protected:
    std::string ruleset_version_;
    std::string error_;
    std::map<std::string, section_info, std::less<>> sections_;
};

} // namespace ddwaf
