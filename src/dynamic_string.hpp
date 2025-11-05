// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fmt/core.h>
#include <fmt/format.h>
#include <limits>
#include <new>
#include <string>
#include <string_view>

#include "memory_resource.hpp"
#include "pointer.hpp"

namespace ddwaf {

class owned_object;

// This is a modifiable string type which allows transferring ownership  the
// internal buffer. This is particularly useful for strings which ultimately
// result in an output object, as it prevents copying unnecessary strings.
class dynamic_string {
public:
    using size_type = uint32_t;

    dynamic_string() = default;

    explicit dynamic_string(size_type capacity,
        nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource())
        : alloc_(alloc)
    {
        ensure_spare_capacity(capacity);
    }

    dynamic_string(const char *str, size_type size,
        nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource())
        : alloc_(alloc)
    {
        ensure_spare_capacity(size);
        if (size != 0) {
            memcpy(buffer_, str, size);
            size_ = size;
        }
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(std::string_view str,
        nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource())
        : dynamic_string(str.data(), str.size(), alloc)
    {}

    dynamic_string(
        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        char *ptr, size_type size, size_type capacity, nonnull_ptr<memory::memory_resource> alloc)
        : alloc_(alloc), buffer_(ptr), size_(size), capacity_(capacity)
    {}

    dynamic_string(const char *str) = delete;

    template <typename T>
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(
        T str, nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource())
        requires std::is_convertible_v<T, std::string_view>
        : dynamic_string(std::string_view{str}, alloc)
    {}

    ~dynamic_string()
    {
        if (buffer_ != nullptr) {
            alloc_->deallocate(buffer_, capacity_, alignof(char));
            buffer_ = nullptr;
            size_ = capacity_ = 0;
        }
    }

    dynamic_string(const dynamic_string &str) : dynamic_string(str.data(), str.size(), str.alloc())
    {}

    dynamic_string &operator=(const dynamic_string &str)
    {
        if (this == &str) {
            return *this;
        }

        return (*this = dynamic_string(str.data(), str.size(), str.alloc()));
    }

    // For performance reasons, a move construction, move assignment or move to
    // object leaves the original string in an unusable state and must be
    // reinitialised if reuse is required.
    dynamic_string(dynamic_string &&other) noexcept
        : alloc_(other.alloc_), buffer_(other.buffer_), size_(other.size_),
          capacity_(other.capacity_)
    {
        other.buffer_ = nullptr;
        other.size_ = other.capacity_ = 0;
    }

    dynamic_string &operator=(dynamic_string &&other) noexcept
    {
        if (buffer_ != nullptr) {
            alloc_->deallocate(buffer_, capacity_, alignof(char));
        }

        alloc_ = other.alloc_;
        buffer_ = other.buffer_;
        size_ = other.size_;
        capacity_ = other.capacity_;

        other.buffer_ = nullptr;
        other.size_ = other.capacity_ = 0;

        return *this;
    }

    // This method moves the contents of the string into the resulting object
    owned_object to_object(
        nonnull_ptr<memory::memory_resource> alloc = memory::get_default_resource());

    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type capacity() const noexcept { return capacity_; }
    [[nodiscard]] const char *data() const noexcept { return buffer_; }
    [[nodiscard]] nonnull_ptr<memory::memory_resource> alloc() const noexcept { return alloc_; }

    char &operator[](size_type pos) { return buffer_[pos]; }

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

    void resize(size_type count)
    {
        if (count > size_) {
            ensure_spare_capacity(count - size_);
        }
        size_ = count;
    }

    void resize(size_type count, char c)
    {
        if (count > size_) {
            ensure_spare_capacity(count - size_);
            memset(&buffer_[size_], c, count - size_);
        }
        size_ = count;
    }

    void reserve(size_type count) { ensure_spare_capacity(count); }

    void clear() { size_ = 0; }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    operator std::string_view() const noexcept { return {buffer_, size_}; }
    explicit operator std::string() const { return {buffer_, size_}; }

    bool operator==(const dynamic_string &other) const noexcept
    {
        return size_ == other.size_ && (size_ == 0 || memcmp(buffer_, other.buffer_, size_) == 0);
    }

protected:
    void ensure_spare_capacity(size_type at_least)
    {
        if (at_least > (capacity_ - size_)) {
            // The amount of memory we need to allocate
            auto required_mem = at_least - (capacity_ - size_);

            // The amount of memory we can allocate
            auto available_mem = std::numeric_limits<size_type>::max() - capacity_;
            if (available_mem < required_mem) {
                // The amount of memory we need to allocate is lower than what is available
                // within the current range of size_type
                throw std::bad_alloc{};
            }

            // We have established that available_mem is greater or equal than required_mem and
            // that it fits within our available range. Ideally we'd like to duplicate the
            // capacity, unless required_mem is greater, so we pick the maximum between these two.
            // Conversely, capacity may be greater than available_mem, so pick the minimum between
            // the two.
            auto new_capacity =
                capacity_ + std::min(std::max(capacity_, required_mem), available_mem);
            char *new_buffer = static_cast<char *>(alloc_->allocate(new_capacity, alignof(char)));
            if (buffer_ != nullptr) {
                memcpy(new_buffer, buffer_, size_);
                alloc_->deallocate(buffer_, capacity_, alignof(char));
            }

            buffer_ = new_buffer;
            capacity_ = new_capacity;
        }
    }

    nonnull_ptr<memory::memory_resource> alloc_{memory::get_default_resource()};

    char *buffer_{nullptr};
    // Size explicitly excludes the null character, while capacity includes it
    // as if refers to the total memory allocated.
    size_type size_{0};
    size_type capacity_{0};
};

template <> struct fmt::formatter<dynamic_string> : fmt::formatter<std::string_view> {
    // Use the parse method from the base class formatter
    template <typename FormatContext> auto format(const dynamic_string &d, FormatContext &ctx) const
    {
        return fmt::formatter<std::string_view>::format(std::string_view{d.data(), d.size()}, ctx);
    }
};

} // namespace ddwaf
