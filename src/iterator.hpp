// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "exclusion/common.hpp"
#include "object.hpp"
#include "object_type.hpp"

// Eventually object will be a class rather than a namespace
namespace ddwaf {

// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
template <typename T, std::size_t InlineCapacity> class small_vector {
public:
    static_assert(InlineCapacity > 0);

    small_vector() = default;
    ~small_vector()
    {
        if (!using_overflow_) {
            clear_inline();
        }
    }

    small_vector(const small_vector &) = delete;
    small_vector(small_vector &&) noexcept = delete;
    small_vector &operator=(const small_vector &) = delete;
    small_vector &operator=(small_vector &&) noexcept = delete;

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }

    void clear()
    {
        if (!using_overflow_) {
            clear_inline();
        } else {
            clear_overflow();
        }
        size_ = 0;
    }

    template <typename... Args> T &emplace_back(Args &&...args)
    {
        if (using_overflow_) {
            T &ref = overflow_.emplace_back(std::forward<Args>(args)...);
            size_ = overflow_.size();
            return ref;
        }

        if (size_ < InlineCapacity) {
            T *ptr = inline_ptr_no_obj(size_);
            std::construct_at(ptr, std::forward<Args>(args)...);
            ++size_;
            return *ptr;
        }

        spill_to_overflow();
        T &ref = overflow_.emplace_back(std::forward<Args>(args)...);
        size_ = overflow_.size();
        return ref;
    }

    void pop_back()
    {
        if (using_overflow_) {
            overflow_.pop_back();
            size_ = overflow_.size();
            return;
        }
        --size_;
        std::destroy_at(inline_ptr(size_));
    }

    [[nodiscard]] T &front() { return (*this)[0]; }
    [[nodiscard]] const T &front() const { return (*this)[0]; }
    [[nodiscard]] T &back() { return (*this)[size_ - 1]; }
    [[nodiscard]] const T &back() const { return (*this)[size_ - 1]; }

    [[nodiscard]] T &operator[](std::size_t index)
    {
        return using_overflow_ ? overflow_[index] : *inline_ptr(index);
    }
    [[nodiscard]] const T &operator[](std::size_t index) const
    {
        return using_overflow_ ? overflow_[index] : *inline_ptr(index);
    }

    [[nodiscard]] T *begin() noexcept { return size_ == 0 ? nullptr : data(); }
    [[nodiscard]] T *end() noexcept { return size_ == 0 ? nullptr : data() + size_; }
    [[nodiscard]] const T *begin() const noexcept { return size_ == 0 ? nullptr : data(); }
    [[nodiscard]] const T *end() const noexcept { return size_ == 0 ? nullptr : data() + size_; }

private:
    [[nodiscard]] T *inline_ptr_no_obj(std::size_t index) noexcept
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<T *>(inline_storage_ + (index * sizeof(T)));
    }
    [[nodiscard]] T *inline_ptr(std::size_t index) noexcept
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::launder(reinterpret_cast<T *>(inline_storage_ + (index * sizeof(T))));
    }
    [[nodiscard]] const T *inline_ptr(std::size_t index) const noexcept
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::launder(reinterpret_cast<const T *>(inline_storage_ + (index * sizeof(T))));
    }

    [[nodiscard]] T *data() noexcept { return using_overflow_ ? overflow_.data() : inline_ptr(0); }
    [[nodiscard]] const T *data() const noexcept
    {
        return using_overflow_ ? overflow_.data() : inline_ptr(0);
    }

    void clear_overflow()
    {
        if constexpr (std::is_nothrow_move_constructible_v<T>) {
            // Spill reuses the retained capacity, so keep the allocation.
            overflow_.clear();
        } else {
            // Spill builds a fresh temporary and discards this buffer, so
            // holding the allocation buys nothing; free it.
            overflow_ = std::vector<T>{};
        }
        using_overflow_ = false;
    }

    void clear_inline()
    {
        if constexpr (!std::is_trivially_destructible_v<T>) {
            for (std::size_t i = 0; i < size_; ++i) { std::destroy_at(inline_ptr(i)); }
        }
    }

    void spill_to_overflow()
    {
        if constexpr (std::is_nothrow_move_constructible_v<T>) {
            // Moves can't throw, so there is nothing to roll back: reuse the
            // capacity retained from a prior spill/clear cycle in place.
            overflow_.reserve(size_ + 1);
            for (std::size_t i = 0; i < size_; ++i) {
                overflow_.emplace_back(std::move(*inline_ptr(i)));
            }
        } else {
            // move_if_noexcept falls back to a copy that may throw. Build a
            // temporary so a throw unwinds it before any inline element is
            // destroyed, preserving the strong guarantee on the inline buffer.
            std::vector<T> overflow;
            overflow.reserve(size_ + 1);
            for (std::size_t i = 0; i < size_; ++i) {
                overflow.emplace_back(std::move_if_noexcept(*inline_ptr(i)));
            }
            // only reached if every element moved/copied successfully
            overflow_ = std::move(overflow);
        }
        clear_inline();
        using_overflow_ = true;
    }

    // uninitialized storage for the inline elements
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
    alignas(T) std::byte inline_storage_[sizeof(T) * InlineCapacity];
    std::size_t size_{0};
    std::vector<T> overflow_;
    bool using_overflow_{false};
};

template <typename T> class iterator_base {
public:
    ~iterator_base() = default;

    iterator_base(const iterator_base &) = delete;
    iterator_base(iterator_base &&) noexcept = delete;

    iterator_base &operator=(const iterator_base &) = delete;
    iterator_base &operator=(iterator_base &&) noexcept = delete;

    bool operator++();

    [[nodiscard]] explicit operator bool() const { return current_.second.has_value(); }
    [[nodiscard]] std::vector<std::variant<std::string_view, int64_t>> get_current_path() const;

protected:
    static constexpr std::size_t initial_stack_size = 16;
    static constexpr std::size_t initial_path_size = 8;
    using path_element = std::variant<std::string_view, int64_t>;
    using stack_element = std::pair<object_view, std::size_t>;

    // This is only used when the iterator is initialised with a key path,
    // since the iterator doesn't keep track of the root object provided,
    // but only the beginning of the key path, we keep this here so that we
    // can later provide the accurate full key path.
    small_vector<path_element, initial_path_size> path_;

    small_vector<stack_element, initial_stack_size> stack_;
    std::pair<object_view, object_view> current_;

    const object_set_ref &excluded_;

private:
    explicit iterator_base(const object_set_ref &exclude);

    friend T;
};

class value_iterator : public iterator_base<value_iterator> {
public:
    explicit value_iterator(object_view obj,
        std::span<const std::variant<std::string, int64_t>> path, const object_set_ref &exclude);

    ~value_iterator() = default;

    value_iterator(const value_iterator &) = delete;
    value_iterator(value_iterator &&) = delete;

    value_iterator &operator=(const value_iterator &) = delete;
    value_iterator &operator=(value_iterator &&) = delete;

    [[nodiscard]] object_view operator*() { return current_.second; }

    [[nodiscard]] object_type type() const
    {
        return current_.second.has_value() ? current_.second.type() : object_type::invalid;
    }

protected:
    void initialise_cursor(
        object_view obj, std::span<const std::variant<std::string, int64_t>> path);
    void initialise_cursor_with_path(
        object_view obj, std::span<const std::variant<std::string, int64_t>> path);

    void set_cursor_to_next_object();

    friend class iterator_base<value_iterator>;
};

class key_iterator : public iterator_base<key_iterator> {
public:
    explicit key_iterator(object_view obj, std::span<const std::variant<std::string, int64_t>> path,
        const object_set_ref &exclude);

    ~key_iterator() = default;

    key_iterator(const key_iterator &) = delete;
    key_iterator(key_iterator &&) = delete;

    key_iterator &operator=(const key_iterator &) = delete;
    key_iterator &operator=(key_iterator &&) = delete;

    [[nodiscard]] object_type type() const
    {
        return current_.first.has_value() ? object_type::string : object_type::invalid;
    }

    [[nodiscard]] object_view operator*()
    {
        if (!current_.first.has_value()) {
            return {};
        }
        return current_.first;
    }

protected:
    void initialise_cursor(
        object_view obj, std::span<const std::variant<std::string, int64_t>> path);
    void initialise_cursor_with_path(
        object_view obj, std::span<const std::variant<std::string, int64_t>> path);

    void set_cursor_to_next_object();

    friend class iterator_base<key_iterator>;
};

class kv_iterator : public iterator_base<kv_iterator> {
public:
    explicit kv_iterator(object_view obj, std::span<const std::variant<std::string, int64_t>> path,
        const object_set_ref &exclude);

    ~kv_iterator() = default;

    kv_iterator(const kv_iterator &) = delete;
    kv_iterator(kv_iterator &&) = delete;

    kv_iterator &operator=(const kv_iterator &) = delete;
    kv_iterator &operator=(kv_iterator &&) = delete;

    [[nodiscard]] object_type type() const
    {
        if (current_.second.has_value()) {
            if (scalar_value_) {
                return current_.second.type();
            }

            if (current_.first.has_value()) {
                return object_type::string;
            }
        }
        return object_type::invalid;
    }

    [[nodiscard]] object_view operator*()
    {
        if (current_.second.has_value()) {
            if (scalar_value_) {
                return current_.second;
            }

            if (current_.first.has_value()) {
                return current_.first;
            }
        }
        return {};
    }

protected:
    void initialise_cursor(
        object_view obj, std::span<const std::variant<std::string, int64_t>> path);
    void initialise_cursor_with_path(
        object_view obj, std::span<const std::variant<std::string, int64_t>> path);

    void set_cursor_to_next_object();

    bool scalar_value_{false};

    friend class iterator_base<kv_iterator>;
};

} // namespace ddwaf
