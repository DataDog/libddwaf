// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <span>
#include <string_view>
#include <cstring>
#include <cstdlib>

#include "utils.hpp"

namespace ddwaf::fingerprint {

struct string_buffer {
    explicit string_buffer(std::size_t length)
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc, hicpp-no-malloc,cppcoreguidelines-pro-type-reinterpret-cast)
        : buffer(reinterpret_cast<char *>(malloc(sizeof(char) * length))), length(length)
    {
        if (buffer == nullptr) {
            throw std::bad_alloc{};
        }
    }

    char &operator[](std::size_t idx) const { return buffer[idx]; }

    template <std::size_t N>
    [[nodiscard]] std::span<char, N> subspan() {
        return std::span<char, N>{&buffer[index], N};
    }

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
    explicit string_field(std::string_view input): value(input) {}
    ~string_field() override = default;
    string_field(const string_field&) = default;
    string_field(string_field&&) = default;
    string_field& operator=(const string_field&) = default;
    string_field& operator=(string_field&&) = default;

    std::size_t length() override { return value.size(); }
    void operator()(string_buffer &output) override {
        output.append_lowercase(value);
    }

    std::string_view value;
};

struct string_hash_field : field_generator {
    explicit string_hash_field(std::string_view input): value(input) {}
    ~string_hash_field() override = default;
    string_hash_field(const string_hash_field&) = default;
    string_hash_field(string_hash_field&&) = default;
    string_hash_field& operator=(const string_hash_field&) = default;
    string_hash_field& operator=(string_hash_field&&) = default;

    std::size_t length() override { return value.size(); }
    void operator()(string_buffer &output) override;

    std::string_view value;
};


struct key_hash_field : field_generator {
    explicit key_hash_field(const ddwaf_object &input): value(input) {}
    ~key_hash_field() override = default;
    key_hash_field(const key_hash_field&) = default;
    key_hash_field(key_hash_field&&) = default;
    key_hash_field& operator=(const key_hash_field&) = default;
    key_hash_field& operator=(key_hash_field&&) = default;

    std::size_t length() override {
        return value.type == DDWAF_OBJ_MAP ? value.nbEntries : 0;
    }
    void operator()(string_buffer &output) override;

    ddwaf_object value;
};

struct value_hash_field : field_generator {
    explicit value_hash_field(const ddwaf_object &input): value(input) {}
    ~value_hash_field() override = default;
    value_hash_field(const value_hash_field&) = default;
    value_hash_field(value_hash_field&&) = default;
    value_hash_field& operator=(const value_hash_field&) = default;
    value_hash_field& operator=(value_hash_field&&) = default;

    std::size_t length() override {
        return value.type == DDWAF_OBJ_MAP ? value.nbEntries : 0;
    }
    void operator()(string_buffer &output) override;

    ddwaf_object value;
};

template <typename T, typename... Rest>
std::size_t generate_fragment_length(T &generator, Rest... rest)
{
    if constexpr (sizeof...(rest) > 0) {
        return generator.length() + generate_fragment_length(rest...);
    } else {
        return generator.length();
    }
}

template <typename T, typename... Rest>
void generate_fragment_field(string_buffer &buffer, T &generator, Rest... rest)
{
    generator(buffer);
    if constexpr (sizeof...(rest) > 0) {
        buffer.append('-');
        generate_fragment_field(buffer, rest...);
    }
}

template <typename... Args>
ddwaf_object generate_fragment(std::string_view header, Args... generators)
{
    std::size_t total_length = header.size() + 1 + generate_fragment_length(generators...);

    string_buffer buffer{total_length};
    buffer.append_lowercase(header);
    buffer.append('-');

    generate_fragment_field(buffer, generators...);

    ddwaf_object res;
    auto [ptr, size] = buffer.move();
    ddwaf_object_stringl_nc(&res, ptr, size);

    return res;
}

} // namespace ddwaf::fingerprint
