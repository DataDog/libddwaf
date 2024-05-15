// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <cstring>
#include <ddwaf.h>
#include <memory_resource>
#include <stdexcept>
#include <string_view>

#include "utils.hpp"

namespace ddwaf {

class cow_string {
public:
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
    cow_string(cow_string &&other) = delete;
    cow_string &operator=(cow_string &&other) = delete;

    ~cow_string()
    {
        [[likely]] if (modified_) {
            auto *alloc = std::pmr::new_delete_resource();
            alloc->deallocate(buffer_, allocated_length_, alignof(char)); // delete[] buffer_;
        }
    }

    template <typename T = char> [[nodiscard]] constexpr T at(std::size_t idx) const
    {
        return static_cast<T>(buffer_[idx]);
    }

    char &operator[](std::size_t idx)
    {
        force_copy(length_);
        return buffer_[idx];
    }

    bool copy_char(std::size_t from, std::size_t to)
    {
        if (to != from) {
            force_copy(length_);
            buffer_[to] = buffer_[from];
            return true;
        }
        return false;
    }

    constexpr explicit operator std::string_view() { return {buffer_, length_}; }

    [[nodiscard]] constexpr std::size_t length() const { return length_; }
    [[nodiscard]] constexpr const char *data() const { return buffer_; }
    [[nodiscard]] char *modifiable_data()
    {
        force_copy(length_);
        return buffer_;
    }
    // Used for testing purposes
    [[nodiscard]] constexpr bool modified() const { return modified_; }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    [[nodiscard]] std::pair<bool, std::size_t> find(char c, std::size_t start = 0) const
    {
        for (std::size_t i = start; i < length_; ++i) {
            if (buffer_[i] == c) {
                return {true, i};
            }
        }
        return {false, 0};
    }

    // Replaces the internal buffer, ownership is transferred
    void replace_buffer(char *str, std::size_t length)
    {
        [[likely]] if (modified_) {
            auto *alloc = std::pmr::new_delete_resource();
            alloc->deallocate(buffer_, allocated_length_, alignof(char)); // delete[] buffer_;
        }

        modified_ = true;
        buffer_ = str;
        length_ = length;
        allocated_length_ = length;
    }

    // Moves the contents and invalidates the string if the buffer has been
    // modified, otherwise it does nothing
    std::pair<char *, std::size_t> move()
    {
        // TODO String capacity?
        if (modified_ && allocated_length_ != length_) {
            auto *alloc = std::pmr::new_delete_resource();
            char *new_copy = static_cast<char *>(alloc->allocate(length_, alignof(char)));
            if (new_copy == nullptr) {
                throw std::bad_alloc();
            }
            std::memcpy(new_copy, buffer_, length_);
            replace_buffer(new_copy, length_);
        } else {
            force_copy(length_);
        }

        std::pair<char *, std::size_t> res{buffer_, length_};
        modified_ = false;
        buffer_ = nullptr;
        length_ = 0;
        return res;
    }

    // Update length and nul-terminate, allocate if not allocated
    void truncate(std::size_t length)
    {
        [[likely]] if (modified_) {
            length_ = length;
        } else {
            force_copy(length);
        }
    }

protected:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void force_copy(std::size_t bytes)
    {
        [[unlikely]] if (!modified_) {
            auto *alloc = std::pmr::new_delete_resource();
            char *new_copy = static_cast<char *>(
                alloc->allocate(bytes, alignof(char))); // static_cast<char *>(malloc(bytes + 1));
            if (new_copy == nullptr) {
                throw std::bad_alloc();
            }

            std::memcpy(new_copy, buffer_, bytes);

            buffer_ = new_copy;
            modified_ = true;
            length_ = bytes;
            allocated_length_ = bytes;
        }
    }

    bool modified_{false};
    char *buffer_{nullptr};
    std::size_t length_;
    std::size_t allocated_length_;
};

} // namespace ddwaf
