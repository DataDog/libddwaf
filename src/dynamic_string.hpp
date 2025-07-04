// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fmt/core.h>
#include <fmt/format.h>
#include <limits>
#include <string>
#include <string_view>

#include "memory_resource.hpp"

namespace ddwaf {

class owned_object;

// This is a modifiable string type which allows transferring ownership  the
// internal buffer. This is particularly useful for strings which ultimately
// result in an output object, as it prevents copying unnecessary strings.
class dynamic_string {
public:
    using size_type = uint32_t;

    dynamic_string() = default;

    explicit dynamic_string(size_type capacity) { ensure_spare_capacity(capacity); }

    dynamic_string(const char *str, size_type size) : size_(size)
    {
        ensure_spare_capacity(size_);
        if (size_ != 0) {
            memcpy(buffer_, str, size_);
        }
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

    ~dynamic_string()
    {
        if (buffer_ != nullptr) {
            alloc_->deallocate(buffer_, capacity_, alignof(char));
            buffer_ = nullptr;
            size_ = capacity_ = 0;
        }
    }

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
        : buffer_(other.buffer_), size_(other.size_), capacity_(other.capacity_)
    {
        other.buffer_ = nullptr;
        other.size_ = other.capacity_ = 0;
    }

    dynamic_string &operator=(dynamic_string &&other) noexcept
    {
        if (buffer_ != nullptr) {
            alloc_->deallocate(buffer_, capacity_, alignof(char));
        }

        buffer_ = other.buffer_;
        size_ = other.size_;
        capacity_ = other.capacity_;

        other.buffer_ = nullptr;
        other.size_ = other.capacity_ = 0;

        return *this;
    }

    // This method moves the contents of the string into the resulting object
    owned_object to_object();

    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type capacity() const noexcept { return capacity_; }
    [[nodiscard]] const char *data() const noexcept { return buffer_; }

    void append(std::string_view str)
    {
        ensure_spare_capacity(str.size());
        if (!str.empty()) [[likely]] {
            memcpy(&buffer_[size_], str.data(), str.size());
            size_ += str.size();
        }
    }

    void append(char c)
    {
        ensure_spare_capacity(1);
        buffer_[size_++] = c;
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    operator std::string_view() const noexcept { return {buffer_, size_}; }
    explicit operator std::string() const { return {buffer_, size_}; }

    bool operator==(const dynamic_string &other) const noexcept
    {
        return size_ == other.size_ && (size_ == 0 || memcmp(buffer_, other.buffer_, size_) == 0);
    }

    template <typename T> static dynamic_string from_movable_string(T &str)
    {
        dynamic_string dynstr;
        auto [ptr, size] = str.move();
        dynstr.buffer_ = ptr;
        dynstr.size_ = size;
        return dynstr;
    }

protected:
    void ensure_spare_capacity(size_type at_least)
    {
        if (at_least == 0) {
            return;
        }

        if (at_least > (std::numeric_limits<size_type>::max() - capacity_)) {
            throw std::bad_alloc{};
        }

        if ((size_ + at_least) >= capacity_) {
            auto new_capacity = capacity_ + std::max(capacity_, at_least);
            char *new_buffer = static_cast<char *>(alloc_->allocate(new_capacity, alignof(char)));
            if (buffer_ != nullptr) {
                memcpy(new_buffer, buffer_, size_);
                alloc_->deallocate(buffer_, capacity_, alignof(char));
            }

            buffer_ = new_buffer;
            capacity_ = new_capacity;
        }
    }

    memory::memory_resource *alloc_{memory::get_default_resource()};

    char *buffer_{nullptr};
    // Size explicitly excludes the null character, while capacity includes it
    // as if refers to the total memory allocated.
    size_type size_{0};
    size_type capacity_{0};
};

template <> struct fmt::formatter<dynamic_string> : fmt::formatter<std::string_view> {
    // Use the parse method from the base class formatter
    template <typename FormatContext> auto format(const dynamic_string &d, FormatContext &ctx)
    {
        return fmt::formatter<std::string_view>::format(std::string_view{d.data(), d.size()}, ctx);
    }
};

} // namespace ddwaf
