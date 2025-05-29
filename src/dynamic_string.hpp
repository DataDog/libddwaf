// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

namespace ddwaf {

class owned_object;

// This is a modifiable string type which allows transferring ownership  the
// internal buffer. This is particularly useful for strings which ultimately
// result in an output object, as it prevents copying unnecessary strings.
class dynamic_string {
public:
    dynamic_string() : dynamic_string(static_cast<std::size_t>(0)){};

    explicit dynamic_string(std::size_t capacity)
    {
        ensure_spare_capacity(capacity);
        buffer_.get()[0] = '\0';
    }

    dynamic_string(const char *str, std::size_t size) : size_(size)
    {
        ensure_spare_capacity(size_);
        if (size_ != 0) {
            memcpy(buffer_.get(), str, size_);
        }
        buffer_.get()[size_] = '\0';
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(std::string_view str) : dynamic_string(str.data(), str.size()) {}

    dynamic_string(const char *str) = delete;

    template <typename T>
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(T str)
        requires std::is_constructible_v<std::string_view, T>
        : dynamic_string(std::string_view{str})
    {}

    ~dynamic_string() = default;

    dynamic_string(const dynamic_string &str) : dynamic_string(str.data(), str.size()) {}

    dynamic_string &operator=(const dynamic_string &str)
    {
        if (this == &str) {
            return *this;
        }

        return (*this = dynamic_string(std::string_view{str}));
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

    // This method moves the contents of the string into the resulting object
    owned_object to_object();

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] const char *data() const noexcept { return buffer_.get(); }

    void append(std::string_view str)
    {
        ensure_spare_capacity(str.size());
        if (!str.empty()) [[likely]] {
            memcpy(&buffer_.get()[size_], str.data(), str.size());
            size_ += str.size();
        }
        buffer_.get()[size_] = '\0';
    }

    void append(char c)
    {
        ensure_spare_capacity(1);
        buffer_.get()[size_++] = c;
        buffer_.get()[size_] = '\0';
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    operator std::string_view() const noexcept { return {buffer_.get(), size_}; }
    explicit operator std::string() const { return {buffer_.get(), size_}; }

    bool operator==(const dynamic_string &other) const noexcept
    {
        return size_ == other.size_ && (memcmp(buffer_.get(), other.buffer_.get(), size_) == 0);
    }

protected:
    void ensure_spare_capacity(std::size_t at_least)
    {
        // We need to be able to allocate at_least + 1 to include the null character
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

            if (buffer_) {
                memcpy(new_buffer, buffer_.get(), size_);
            }

            buffer_.reset(new_buffer);
            capacity_ = new_capacity_;
        }
    }

    std::unique_ptr<char, decltype(&free)> buffer_{nullptr, free};
    // Size explicitly excludes the null character, while capacity includes it
    // as if refers to the total memory allocated.
    std::size_t size_{0};
    std::size_t capacity_{0};
};

} // namespace ddwaf
