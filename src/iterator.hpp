// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <span>
#include <string>
#include <vector>

#include "exclusion/common.hpp"
#include "object.hpp"
#include "utils.hpp"

namespace ddwaf {

template <typename T> class iterator_base {
public:
    explicit iterator_base(
        const exclusion::object_set_ref &exclude, const object_limits &limits = object_limits());
    ~iterator_base() = default;

    iterator_base(const iterator_base &) = default;
    iterator_base(iterator_base &&) noexcept = default;

    iterator_base &operator=(const iterator_base &) = delete;
    iterator_base &operator=(iterator_base &&) noexcept = delete;

    bool operator++();

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
    std::vector<detail::object_iterator> stack_;

    std::pair<object_view, object_view> current_;

    const exclusion::object_set_ref &excluded_;
};

class value_iterator : public iterator_base<value_iterator> {
public:
    explicit value_iterator(object_view obj, std::span<const std::string> path,
        const exclusion::object_set_ref &exclude, const object_limits &limits = object_limits());

    ~value_iterator() = default;

    value_iterator(const value_iterator &) = default;
    value_iterator(value_iterator &&) = default;

    value_iterator &operator=(const value_iterator &) = delete;
    value_iterator &operator=(value_iterator &&) = delete;

    [[nodiscard]] explicit operator bool() const { return current_.second.has_value(); }
    [[nodiscard]] object_view operator*() const { return current_.second; }

    [[nodiscard]] object_type type() const { return current_.second.type(); }

protected:
    void initialise_cursor(object_view obj, std::span<const std::string> path);
    void initialise_cursor_with_path(object_view obj, std::span<const std::string> path);

    void set_cursor_to_next_object();

    friend class iterator_base<value_iterator>;
};

class key_iterator : public iterator_base<key_iterator> {
public:
    explicit key_iterator(object_view obj, std::span<const std::string> path,
        const exclusion::object_set_ref &exclude, const object_limits &limits = object_limits());

    ~key_iterator() = default;

    key_iterator(const key_iterator &) = default;
    key_iterator(key_iterator &&) = delete;

    key_iterator &operator=(const key_iterator &) = delete;
    key_iterator &operator=(key_iterator &&) = delete;

    [[nodiscard]] object_type type() const { return current_.first.type(); }

    [[nodiscard]] object_view operator*() { return current_.first; }
    [[nodiscard]] explicit operator bool() const { return current_.first.has_value(); }

protected:
    void initialise_cursor(object_view obj, std::span<const std::string> path);
    void initialise_cursor_with_path(object_view obj, std::span<const std::string> path);

    void set_cursor_to_next_object();

    friend class iterator_base<key_iterator>;
};

class kv_iterator : public iterator_base<kv_iterator> {
public:
    explicit kv_iterator(object_view obj, std::span<const std::string> path,
        const exclusion::object_set_ref &exclude, const object_limits &limits = object_limits());

    ~kv_iterator() = default;

    kv_iterator(const kv_iterator &) = default;
    kv_iterator(kv_iterator &&) = delete;

    kv_iterator &operator=(const kv_iterator &) = delete;
    kv_iterator &operator=(kv_iterator &&) = delete;

    [[nodiscard]] explicit operator bool() const { return current_.second.has_value(); }

    [[nodiscard]] object_type type() const
    {
        if (scalar_value_) {
            return current_.second.type();
        }
        return current_.first.type();
    }

    [[nodiscard]] object_view operator*() const
    {
        if (scalar_value_) {
            return current_.second;
        }
        return current_.first;
    }

protected:
    void initialise_cursor(object_view obj, std::span<const std::string> path);
    void initialise_cursor_with_path(object_view obj, std::span<const std::string> path);

    void set_cursor_to_next_object();

    bool scalar_value_{false};

    // TODO treat a map as an array and iterate as normal, this would simplify
    // the logic as one wouldn't need to keep track of whether we're looking at
    // a key or a value

    friend class iterator_base<kv_iterator>;
};

} // namespace ddwaf
