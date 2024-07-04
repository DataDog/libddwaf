// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <span>

#include "sha256.hpp"
#include "transformer/lowercase.hpp"

namespace ddwaf::fingerprint {

struct string_buffer {
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc, hicpp-no-malloc,
    // cppcoreguidelines-pro-type-reinterpret-cast)
    explicit string_buffer(std::size_t length)
        : buffer(reinterpret_cast<char *>(malloc(sizeof(char) * length))), length(length)
    {
        if (buffer == nullptr) {
            throw std::bad_alloc{};
        }
    }

    char &operator[](std::size_t idx) const { return buffer[idx]; }

    [[nodiscard]] std::span<char> subspan(std::size_t len) const { return {&buffer[index], len}; }

    void append(std::string_view str)
    {
        memcpy(&buffer[index], str.data(), str.size());
        index += str.size();
    }

    void append_lowercase(std::string_view str)
    {
        for (auto c : str) { buffer[index++] = ddwaf::tolower(c); }
    }

    template <std::size_t N> void append(std::array<char, N> str)
    {
        memcpy(&buffer[index], str.data(), str.size());
        index += str.size();
    }

    template <std::size_t N> void append_lowercase(std::array<char, N> str)
    {
        for (auto c : str) { buffer[index++] = ddwaf::tolower(c); }
    }

    void append(char c) { buffer[index++] = c; }

    std::pair<char *, std::size_t> move()
    {
        auto *ptr = buffer;
        buffer = nullptr;
        return {ptr, index};
    }

    char *buffer{nullptr};
    std::size_t index{0};
    std::size_t length;
};

struct field_generator {
    field_generator() = default;
    virtual ~field_generator() = default;
    field_generator(const field_generator&) = default;
    field_generator(field_generator&&) = default;
    field_generator& operator=(const field_generator&) = default;
    field_generator& operator=(field_generator&&) = default;

    virtual std::size_t length() = 0;
    virtual void operator()(string_buffer &output) = 0;
};

struct string_field : field_generator {
    string_field() = default;
    ~string_field() override = default;
    string_field(const string_field&) = default;
    string_field(string_field&&) = default;
    string_field& operator=(const string_field&) = default;
    string_field& operator=(string_field&&) = default;

    std::size_t length() override;
    void operator()(string_buffer &output) override;
};

struct key_hash_field : field_generator {
    key_hash_field() = default;
    ~key_hash_field() override = default;
    key_hash_field(const key_hash_field&) = default;
    key_hash_field(key_hash_field&&) = default;
    key_hash_field& operator=(const key_hash_field&) = default;
    key_hash_field& operator=(key_hash_field&&) = default;

    std::size_t length() override;
    void operator()(string_buffer &output) override;
};

struct value_hash_field : field_generator {
    value_hash_field() = default;
    ~value_hash_field() override = default;
    value_hash_field(const value_hash_field&) = default;
    value_hash_field(value_hash_field&&) = default;
    value_hash_field& operator=(const value_hash_field&) = default;
    value_hash_field& operator=(value_hash_field&&) = default;

    std::size_t length() override;
    void operator()(string_buffer &output) override;
};

template <std::size_t N>
ddwaf_object generate_fragment(std::string_view header, std::array<field_generator&, N> generators)
{
    std::size_t total_length = header.size() + 1;
    for (auto & generator : generators) {
        total_length += generator.length();
    }

    string_buffer buffer{total_length};
    buffer.append_lowercase(header);
    buffer.append('-');

    for (auto & generator : generators) {
       generator(buffer);
    }

    ddwaf_object res;
    auto [ptr, size] = buffer.move();
    ddwaf_object_stringl_nc(&res, ptr, size);

    return res;
}

} // namespace ddwaf::fingerprint
