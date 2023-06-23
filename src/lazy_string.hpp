// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <cstring>
#include <ddwaf.h>
#include <stdexcept>
#include <string_view>

namespace ddwaf {

class lazy_string {
public:
    explicit lazy_string(std::string_view original)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        : copy_(const_cast<char *>(original.data())), length_(original.length())
    {}

    lazy_string(const lazy_string &) = delete;
    lazy_string &operator=(const lazy_string &) = delete;

    lazy_string(lazy_string &&other) noexcept
        : modified_(other.modified_), copy_(other.copy_), length_(other.length_)
    {
        other.modified_ = false;
        other.copy_ = nullptr;
    }

    lazy_string &operator=(lazy_string &&other) noexcept
    {
        modified_ = other.modified_;
        copy_ = other.copy_;

        other.modified_ = false;
        other.copy_ = nullptr;

        return *this;
    }

    ~lazy_string()
    {
        if (modified_) {
            // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-no-malloc)
            free(copy_);
        }
    }

    [[nodiscard]] constexpr const char &at(std::size_t idx) const { return copy_[idx]; }

    char &operator[](std::size_t idx)
    {
        force_copy(length_);
        return copy_[idx];
    }

    constexpr explicit operator std::string_view() { return {copy_, length_}; }

    [[nodiscard]] constexpr std::size_t length() const { return length_; }
    [[nodiscard]] constexpr bool modified() const { return modified_; }
    [[nodiscard]] constexpr const char *value() const { return copy_; }
    [[nodiscard]] constexpr char *data() { return modified_ ? copy_ : nullptr; }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    [[nodiscard]] std::pair<bool, std::size_t> find(char c, std::size_t start) const
    {
        for (std::size_t i = start; i < length_; ++i) {
            if (copy_[i] == c) {
                return {true, i};
            }
        }
        return {false, 0};
    }

    // Reset the internal buffer, ownership is transferred
    void reset(char *str, std::size_t length)
    {
        if (modified_) {
            // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-no-malloc)
            free(copy_);
        }

        modified_ = true;
        copy_ = str;
        length_ = length;
    }

    // Update length and nul-terminate, allocate if not allocated
    void finalize() { return finalize(length_); }
    void finalize(std::size_t length)
    {
        if (modified_) {
            length_ = length;
            copy_[length] = '\0';
        } else {
            force_copy(length);
        }
    }

protected:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void force_copy(std::size_t bytes)
    {
        if (!modified_) {
            // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-no-malloc)
            char *new_copy = static_cast<char *>(malloc(bytes + 1));
            if (new_copy == nullptr) {
                throw std::bad_alloc();
            }

            memcpy(new_copy, copy_, bytes);
            new_copy[bytes] = '\0';

            copy_ = new_copy;
            modified_ = true;
        }
    }

    bool modified_{false};
    char *copy_{nullptr};
    std::size_t length_;
};

} // namespace ddwaf
