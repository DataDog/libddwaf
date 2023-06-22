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
        : original_(original), length_(original.length())
    {}

    lazy_string(const lazy_string &) = delete;
    lazy_string &operator=(const lazy_string &) = delete;

    lazy_string(lazy_string &&other) noexcept
        : original_(other.original_), length_(other.length_), copy_(other.copy_)
    {
        other.copy_ = nullptr;
    }

    lazy_string &operator=(lazy_string &&other) noexcept
    {
        original_ = other.original_;
        copy_ = other.copy_;
        other.copy_ = nullptr;
        return *this;
    }

    ~lazy_string()
    {
        // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-no-malloc)
        free(copy_);
    }

    [[nodiscard]] constexpr char at(std::size_t idx) const { return original_[idx]; }

    char &operator[](std::size_t idx)
    {
        force_copy(original_.length());
        return copy_[idx];
    }

    [[nodiscard]] constexpr std::size_t length() const { return length_; }
    [[nodiscard]] constexpr bool modified() const { return copy_ != nullptr; }
    [[nodiscard]] constexpr const char *value() const
    {
        return copy_ != nullptr ? copy_ : original_.data();
    }
    [[nodiscard]] constexpr char *data() { return copy_; }

    char *move()
    {
        auto *retval = copy_;

        copy_ = nullptr;
        length_ = 0;
        original_ = {};

        return retval;
    }

    void finalize() { return finalize(length_); }

    void finalize(std::size_t length)
    {
        if (copy_ != nullptr) {
            length_ = length;
            copy_[length] = '\0';
        } else {
            force_copy(length);
        }
        original_ = {copy_, length};
    }

    void reset(char *str, std::size_t length)
    {
        if (copy_ != nullptr) {
            free(copy_);
        }

        copy_ = str;
        length_ = length;
        original_ = {copy_, length_};
    }

protected:
    void force_copy(std::size_t bytes)
    {
        if (copy_ == nullptr) {
            // NOLINTNEXTLINE(hicpp-no-malloc,cppcoreguidelines-no-malloc)
            copy_ = static_cast<char *>(malloc(bytes + 1));
            if (copy_ == nullptr) {
                throw std::bad_alloc();
            }

            memcpy(copy_, original_.data(), bytes);
            copy_[bytes] = '\0';
        }
    }

    std::string_view original_;
    std::size_t length_;
    char *copy_{nullptr};
};

} // namespace ddwaf