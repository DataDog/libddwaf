// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <utility>

#include "dynamic_string.hpp"
#include "memory_resource.hpp"
#include "pointer.hpp"

namespace ddwaf {

class cow_string {
public:
    using size_type = uint32_t;

    explicit cow_string(std::string_view original)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        : buffer_(const_cast<char *>(original.data())), length_(original.length())
    {
        [[unlikely]] if (buffer_ == nullptr) {
            throw std::runtime_error{"cow_string initialised with nullptr"};
        }
    }
    cow_string(const cow_string &) = delete;
    cow_string &operator=(const cow_string &) = delete;
    cow_string(cow_string &&other) noexcept
        : buffer_(other.buffer_), length_(other.length_), capacity_(other.capacity_)
    {
        other.buffer_ = nullptr;
        other.length_ = other.capacity_ = 0;
    }
    cow_string &operator=(cow_string &&other) = delete;

    ~cow_string()
    {
        [[likely]] if (capacity_ > 0 && buffer_ != nullptr) {
            alloc_->deallocate(buffer_, capacity_, alignof(char));
        }
    }

    template <typename T = char> [[nodiscard]] constexpr T at(size_type idx) const
    {
        return static_cast<T>(buffer_[idx]);
    }

    char &operator[](size_type idx)
    {
        force_copy(length_);
        return buffer_[idx];
    }

    bool copy_char(size_type from, size_type to)
    {
        if (to < from && from < length_) {
            force_copy(length_);
            buffer_[to] = buffer_[from];
            return true;
        }
        return false;
    }

    constexpr explicit operator std::string_view() { return {buffer_, length_}; }

    [[nodiscard]] nonnull_ptr<memory::memory_resource> alloc() const noexcept { return alloc_; }
    [[nodiscard]] constexpr size_type length() const noexcept { return length_; }
    [[nodiscard]] constexpr const char *data() const noexcept { return buffer_; }
    [[nodiscard]] char *modifiable_data()
    {
        force_copy(length_);
        return buffer_;
    }
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    [[nodiscard]] std::pair<bool, size_type> find(char c, size_type start = 0) const
    {
        for (size_type i = start; i < length_; ++i) {
            if (buffer_[i] == c) {
                return {true, i};
            }
        }
        return {false, 0};
    }

    // Replaces the internal buffer, ownership is transferred
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void replace_buffer(char *str, size_type length, size_type capacity,
        nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource())
    {
        [[likely]] if (capacity_ > 0) {
            alloc_->deallocate(buffer_, capacity_, alignof(char));
        }

        buffer_ = str;
        length_ = length;
        capacity_ = capacity;
        alloc_ = alloc;
    }

    explicit operator dynamic_string()
    {
        force_copy(length_);

        dynamic_string dynstr{buffer_, length_, capacity_, alloc_};

        buffer_ = nullptr;
        length_ = 0;
        capacity_ = 0;

        return dynstr;
    }

    // Update length and nul-terminate, allocate if not allocated
    void truncate(size_type length)
    {
        [[likely]] if (capacity_ > 0) {
            length_ = length;
        } else {
            force_copy(length);
        }
    }

    // Used for testing purposes, must not be used for anything else
    [[nodiscard]] constexpr bool modified() const noexcept { return capacity_ > 0; }

protected:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void force_copy(size_type bytes)
    {
        if (capacity_ == 0) {
            // Avoid allocating 0-sized strings
            if (bytes == 0) {
                buffer_ = nullptr;
                length_ = 0;
                return;
            }

            char *new_copy = static_cast<char *>(alloc_->allocate(bytes, alignof(char)));
            memcpy(new_copy, buffer_, bytes);

            buffer_ = new_copy;
            length_ = bytes;
            capacity_ = bytes;
        }
    }

    nonnull_ptr<memory::memory_resource> alloc_{memory::get_default_resource()};

    char *buffer_;
    size_type length_;
    size_type capacity_{0};
};

} // namespace ddwaf
