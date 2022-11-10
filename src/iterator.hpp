// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <config.hpp>
#include <cstdint>
#include <functional>
#include <manifest.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utils.h>
#include <vector>

// Eventually object will be a class rather than a namespace
namespace ddwaf::object
{

template <typename T>
class iterator_base
{
public:
    explicit iterator_base(const object_limits &limits = object_limits());
    ~iterator_base() = default;

    iterator_base(const iterator_base&) = default;
    iterator_base(iterator_base&&) noexcept = default;

    iterator_base &operator=(const iterator_base&) = default;
    iterator_base &operator=(iterator_base&&) noexcept = default;

    bool operator++();

    [[nodiscard]] explicit operator bool() const { return current_ != nullptr; }
    [[nodiscard]] size_t depth() { return stack_.size() + path_.size(); }
    [[nodiscard]] std::vector<std::string> get_current_path() const;

protected:
    static constexpr std::size_t initial_stack_size = 32;

    object_limits limits_;
    // This is only used when the iterator is initialised with a key path,
    // since the iterator doesn't keep track of the root object provided,
    // but only the beginning of the key path, we keep this here so that we
    // can later provide the accurate full key path.
    std::vector<std::string> path_;
    std::vector<std::pair<const ddwaf_object *, std::size_t>> stack_;
    const ddwaf_object *current_{nullptr};
};

class value_iterator : public iterator_base<value_iterator>
{
public:
    explicit value_iterator(const ddwaf_object *obj,
        const std::vector<std::string> &path = {},
        const object_limits &limits = object_limits());

    ~value_iterator() = default;

    value_iterator(const value_iterator&) = default;
    value_iterator(value_iterator&&) = default;

    value_iterator &operator=(const value_iterator&) = default;
    value_iterator &operator=(value_iterator&&) = default;

    [[nodiscard]] const ddwaf_object* operator*() {
        return current_;
    }

    [[nodiscard]] DDWAF_OBJ_TYPE type() const {
        return current_ != nullptr ? current_->type : DDWAF_OBJ_INVALID;
    }
protected:
    void initialise_cursor(const ddwaf_object *obj,
        const std::vector<std::string> &path);
    void initialise_cursor_with_path(const ddwaf_object *obj,
        const std::vector<std::string> &path);

    void set_cursor_to_next_object();

    friend class iterator_base<value_iterator>;
};

class key_iterator : public iterator_base<key_iterator>
{
public:
    explicit key_iterator(const ddwaf_object *obj,
        const std::vector<std::string> &path = {},
        const object_limits &limits = object_limits());

    ~key_iterator() = default;

    key_iterator(const key_iterator&) = default;
    key_iterator(key_iterator&&) = delete;

    key_iterator &operator=(const key_iterator&) = default;
    key_iterator &operator=(key_iterator&&) = delete;

    [[nodiscard]] DDWAF_OBJ_TYPE type() const {
        if (current_->parameterName != nullptr) {
            return DDWAF_OBJ_STRING;
        } 
        return DDWAF_OBJ_INVALID;
    }

    [[nodiscard]] const ddwaf_object* operator*() {
        return current_ == nullptr ? nullptr :
            ddwaf_object_stringl_nc(&current_key_,
                current_->parameterName, current_->parameterNameLength);
    }

protected:
    void initialise_cursor(const ddwaf_object *obj,
        const std::vector<std::string> &path);
    void initialise_cursor_with_path(const ddwaf_object *obj,
        const std::vector<std::string> &path);

    void set_cursor_to_next_object();

    ddwaf_object current_key_{};

    friend class iterator_base<key_iterator>;
};

} // namespace ddwaf::object
