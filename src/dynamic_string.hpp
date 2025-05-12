// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include "ddwaf.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>

namespace ddwaf {

class dynamic_string {
public:
    dynamic_string() : dynamic_string(0UL){};

    explicit dynamic_string(std::size_t capacity)
    {
        if (capacity == std::numeric_limits<std::size_t>::max()) {
            throw std::bad_alloc{};
        }

        // Add one more for nul-character which is currently being included to
        // ensure that all output strings are zero-terminated
        capacity_ = capacity + 1;

        // NOLINTNEXTLINE(hicpp-no-malloc)
        buffer_.reset(static_cast<char *>(malloc(capacity_)));
        if (buffer_ == nullptr) {
            throw std::bad_alloc{};
        }

        buffer_.get()[0] = '\0';
    }

    template <typename T>
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(T str)
        requires std::is_same_v<std::string_view, std::decay_t<T>> ||
                 std::is_same_v<std::string, std::decay_t<T>>
        : size_(str.size())
    {
        if (size_ == std::numeric_limits<std::size_t>::max()) {
            throw std::bad_alloc{};
        }

        // Add one more for nul-character which is currently being included to
        // ensure that all output strings are zero-terminated
        capacity_ = size_ + 1;

        // NOLINTNEXTLINE(hicpp-no-malloc)
        buffer_.reset(static_cast<char *>(malloc(capacity_)));
        if (buffer_ == nullptr) {
            throw std::bad_alloc{};
        }

        if (!str.empty()) {
            memcpy(buffer_.get(), str.data(), size_);
        }

        buffer_.get()[size_] = '\0';
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(const char *str) : size_(strlen(str)), capacity_(size_ + 1)
    {
        // NOLINTNEXTLINE(hicpp-no-malloc)
        buffer_.reset(static_cast<char *>(malloc(capacity_)));
        if (buffer_ == nullptr) {
            throw std::bad_alloc{};
        }

        // Copy up to the nul-character
        memcpy(buffer_.get(), str, capacity_);
    }

    ~dynamic_string() = default;

    dynamic_string(const dynamic_string &str)
        // NOLINTNEXTLINE(hicpp-no-malloc)
        : buffer_(static_cast<char *>(malloc(str.capacity())), free), size_(str.size()),
          capacity_(str.capacity())
    {
        if (buffer_ == nullptr) {
            throw std::bad_alloc{};
        }

        // Copy up to the nul-character
        memcpy(buffer_.get(), str.data(), capacity_);
    }

    dynamic_string &operator=(const dynamic_string &str)
    {
        if (this == &str) {
            return *this;
        }

        size_ = str.size();
        capacity_ = str.capacity();

        // NOLINTNEXTLINE(hicpp-no-malloc)
        buffer_.reset(static_cast<char *>(malloc(str.capacity())));
        if (buffer_ == nullptr) {
            throw std::bad_alloc{};
        }

        // Copy up to the nul-character
        memcpy(buffer_.get(), str.data(), capacity_);
        return *this;
    }

    // For performance reasons, a move construction, move assignment or move to
    // object leaves the original string in an unusable state and must be
    // reinitialised if reuse is required.
    dynamic_string(dynamic_string &&other) noexcept
        : buffer_(std::move(other.buffer_)), size_(other.size_), capacity_(other.capacity_)
    {
        other.size_ = other.capacity_ = 0;
    }

    dynamic_string &operator=(dynamic_string &&other) noexcept
    {
        buffer_ = std::move(other.buffer_);
        size_ = other.size_;
        capacity_ = other.capacity_;

        other.size_ = other.capacity_ = 0;

        return *this;
    }

    ddwaf_object move()
    {
        ddwaf_object object;
        ddwaf_object_stringl_nc(&object, buffer_.release(), size_);
        size_ = capacity_ = 0;
        return object; // NOLINT(clang-analyzer-unix.Malloc)
    }

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] const char *data() const noexcept { return buffer_.get(); }

    void append(std::string_view str)
    {
        realloc_if_needed(str.size());
        if (!str.empty()) [[likely]] {
            memcpy(&buffer_.get()[size_], str.data(), str.size());
            size_ += str.size();
        }
        buffer_.get()[size_] = '\0';
    }

    void append(char c)
    {
        realloc_if_needed(1);
        buffer_.get()[size_++] = c;
        buffer_.get()[size_] = '\0';
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    operator std::string_view() const { return {buffer_.get(), size_}; }
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    operator std::string() const { return {buffer_.get(), size_}; }

    bool operator==(const dynamic_string &other) const
    {
        return size_ == other.size_ && (memcmp(buffer_.get(), other.buffer_.get(), size_) == 0);
    }

protected:
    void realloc_if_needed(std::size_t at_least)
    {
        // We need to be able to allocate at_least + 1
        if (at_least >= (std::numeric_limits<std::size_t>::max() - capacity_)) {
            throw std::bad_alloc{};
        }

        if ((size_ + at_least + 1) >= capacity_) {
            auto new_capacity_ = capacity_ + std::max(capacity_, at_least + 1);
            // NOLINTNEXTLINE(hicpp-no-malloc)
            char *new_buffer = static_cast<char *>(malloc(new_capacity_));
            if (new_buffer == nullptr) {
                throw std::bad_alloc{};
            }

            memcpy(new_buffer, buffer_.get(), size_);

            buffer_.reset(new_buffer);
            capacity_ = new_capacity_;
        }
    }

    std::unique_ptr<char, decltype(&free)> buffer_{nullptr, free};
    std::size_t size_{0};
    std::size_t capacity_{0};
};

} // namespace ddwaf
