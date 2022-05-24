// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.


#pragma once

#include <functional>
#include <set>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <IPWRuleProcessor.h>
#include <PWManifest.h>
#include <utils.h>
#include <validator.hpp>

// Eventually object will be a class rather than a namespace
namespace ddwaf::object
{

class iterator_base
{
public:
    explicit iterator_base(const object_limits &limits = object_limits());
    virtual ~iterator_base() = default;

    iterator_base(const iterator_base&) = default;
    iterator_base(iterator_base&&) = default;

    iterator_base &operator=(const iterator_base&) = delete;
    iterator_base &operator=(iterator_base&&) = delete;

    [[nodiscard]] operator bool() const { return current_ != nullptr; }
    [[nodiscard]] bool is_valid() const { return current_ != nullptr; }
    bool operator++();

    // TODO add const, nodiscard, etc
    [[nodiscard]] virtual const ddwaf_object* operator*() {
        return current_;
    }

    [[nodiscard]] virtual DDWAF_OBJ_TYPE type() const { 
        return current_ != nullptr ? current_->type : DDWAF_OBJ_INVALID;
    }

    [[nodiscard]] std::vector<std::string> get_current_path() const;

protected:
    virtual void set_cursor_to_next_object() = 0;

    static constexpr std::size_t initial_stack_size = 32;

    const object_limits limits_;
    std::vector<std::string> path_;
    std::vector<std::pair<const ddwaf_object *, std::size_t>> stack_;
    const ddwaf_object *current_{nullptr};
};

class value_iterator : public iterator_base
{
public:
    explicit value_iterator(const ddwaf_object *obj,
        const std::vector<std::string> &path = {},
        const object_limits &limits = object_limits());

    ~value_iterator() override = default;

    value_iterator(const value_iterator&) = default;
    value_iterator(value_iterator&&) = default;

    value_iterator &operator=(const value_iterator&) = delete;
    value_iterator &operator=(value_iterator&&) = delete;

protected:
    void initialise_cursor(const ddwaf_object *obj,
        const std::vector<std::string> &path);
    void initialise_cursor_with_path(const ddwaf_object *obj,
        const std::vector<std::string> &path);

    void set_cursor_to_next_object() override;
};

class key_iterator : public iterator_base
{
public:
    explicit key_iterator(const ddwaf_object *obj,
        const std::vector<std::string> &path = {},
        const object_limits &limits = object_limits());

    ~key_iterator() override = default;

    key_iterator(const key_iterator&) = default;
    key_iterator(key_iterator&&) = default;

    key_iterator &operator=(const key_iterator&) = delete;
    key_iterator &operator=(key_iterator&&) = delete;

    [[nodiscard]] DDWAF_OBJ_TYPE type() const override {
        if (current_->parameterName != nullptr) {
            return DDWAF_OBJ_STRING;
        } 
        return DDWAF_OBJ_INVALID;
    }

    [[nodiscard]] const ddwaf_object* operator*() override {
        return current_ == nullptr ? nullptr :
            ddwaf_object_stringl_nc(&current_key_,
                current_->parameterName, current_->parameterNameLength);
    }

protected:
    void initialise_cursor(const ddwaf_object *obj,
        const std::vector<std::string> &path);
    void initialise_cursor_with_path(const ddwaf_object *obj,
        const std::vector<std::string> &path);

    void set_cursor_to_next_object() override;

    ddwaf_object current_key_;
};


}
