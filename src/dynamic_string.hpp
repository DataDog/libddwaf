// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "ddwaf.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string_view>

class dynamic_string {
public:
    explicit dynamic_string(std::size_t capacity)
        // NOLINTNEXTLINE(hicpp-no-malloc)
        : buffer(static_cast<char *>(malloc(capacity)), free), capacity_(capacity)
    {
        if (buffer == nullptr) {
            throw std::bad_alloc{};
        }
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    dynamic_string(std::string_view str)
    // NOLINTNEXTLINE(hicpp-no-malloc)
        : buffer(static_cast<char *>(malloc(str.size())), free), size_(str.size()),
          capacity_(str.size())
    {
        if (buffer == nullptr) {
            throw std::bad_alloc{};
        }

        memcpy(buffer.get(), str.data(), str.size());
    }

    ~dynamic_string() = default;

    dynamic_string(const dynamic_string &) = delete;
    dynamic_string &operator=(const dynamic_string &) = delete;

    dynamic_string(dynamic_string &&other) noexcept
        : buffer(std::move(other.buffer)), size_(other.size_), capacity_(other.capacity_)
    {
        other.size_ = other.capacity_ = 0;
    }

    dynamic_string &operator=(dynamic_string &&other) noexcept
    {
        buffer = std::move(other.buffer);
        size_ = other.size_;
        capacity_ = other.capacity_;

        other.size_ = other.capacity_ = 0;

        return *this;
    }

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

    void append(std::string_view str)
    {
        realloc_if_needed(str.size());
        if (!str.empty() && (size_ + str.size()) <= capacity_) [[likely]] {
            memcpy(&buffer.get()[size_], str.data(), str.size());
            size_ += str.size();
        }
    }

    void append(char c)
    {
        realloc_if_needed(1);
        buffer.get()[size_++] = c;
    }

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    operator std::string_view() const { return {buffer.get(), size_}; }

    ddwaf_object move()
    {
        ddwaf_object object;
        ddwaf_object_stringl_nc(&object, buffer.release(), size_);
        size_ = capacity_ = 0;
        return object; // NOLINT(clang-analyzer-unix.Malloc)
    }

    void clear()
    {
        buffer.reset(nullptr);
        size_ = capacity_ = 0;
    }

protected:
    void realloc_if_needed(std::size_t at_least)
    {
        if ((size_ + at_least) >= capacity_) {
            auto new_capacity_ = capacity_ + std::max(capacity_, at_least);
            // NOLINTNEXTLINE(hicpp-no-malloc)
            char *new_buffer = static_cast<char *>(malloc(new_capacity_));
            if (new_buffer == nullptr) {
                throw std::bad_alloc{};
            }

            memcpy(new_buffer, buffer.get(), size_);

            buffer.reset(new_buffer);
            capacity_ = new_capacity_;
        }
    }

    std::unique_ptr<char, decltype(&free)> buffer{nullptr, free};
    std::size_t size_{0};
    std::size_t capacity_{};
};
