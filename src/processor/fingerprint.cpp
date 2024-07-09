// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "processor/fingerprint.hpp"
#include "sha256.hpp"
#include "transformer/lowercase.hpp"

namespace ddwaf {
namespace {

struct string_buffer {
    explicit string_buffer(std::size_t length)
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc,cppcoreguidelines-pro-type-reinterpret-cast)
        : buffer(reinterpret_cast<char *>(malloc(sizeof(char) * length))), length(length)
    {
        if (buffer == nullptr) {
            throw std::bad_alloc{};
        }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc,cppcoreguidelines-pro-type-reinterpret-cast)
    ~string_buffer() { free(buffer); }

    string_buffer(const string_buffer &) = delete;
    string_buffer(string_buffer &&) = delete;

    string_buffer &operator=(const string_buffer &) = delete;
    string_buffer &operator=(string_buffer &&) = delete;

    char &operator[](std::size_t idx) const { return buffer[idx]; }

    template <std::size_t N> [[nodiscard]] std::span<char, N> subspan()
    {
        std::span<char, N> res{&buffer[index], N};
        index += N;
        return res;
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
    field_generator(const field_generator &) = default;
    field_generator(field_generator &&) = default;
    field_generator &operator=(const field_generator &) = default;
    field_generator &operator=(field_generator &&) = default;

    virtual std::size_t length() = 0;
    virtual void operator()(string_buffer &output) = 0;
};

struct string_field : field_generator {
    explicit string_field(std::string_view input) : value(input) {}
    ~string_field() override = default;
    string_field(const string_field &) = default;
    string_field(string_field &&) = default;
    string_field &operator=(const string_field &) = default;
    string_field &operator=(string_field &&) = default;

    std::size_t length() override { return value.size(); }
    void operator()(string_buffer &output) override { output.append_lowercase(value); }

    std::string_view value;
};

struct string_hash_field : field_generator {
    explicit string_hash_field(std::string_view input) : value(input) {}
    ~string_hash_field() override = default;
    string_hash_field(const string_hash_field &) = default;
    string_hash_field(string_hash_field &&) = default;
    string_hash_field &operator=(const string_hash_field &) = default;
    string_hash_field &operator=(string_hash_field &&) = default;

    std::size_t length() override { return 8; }
    void operator()(string_buffer &output) override;

    std::string_view value;
};

struct key_hash_field : field_generator {
    explicit key_hash_field(const ddwaf_object &input) : value(input) {}
    ~key_hash_field() override = default;
    key_hash_field(const key_hash_field &) = default;
    key_hash_field(key_hash_field &&) = default;
    key_hash_field &operator=(const key_hash_field &) = default;
    key_hash_field &operator=(key_hash_field &&) = default;

    std::size_t length() override { return value.type == DDWAF_OBJ_MAP ? 8 : 0; }
    void operator()(string_buffer &output) override;

    ddwaf_object value;
};

template <typename T, typename... Rest>
std::size_t generate_fragment_length(T &generator, Rest... rest)
{
    if constexpr (sizeof...(rest) > 0) {
        return generator.length() + 1 + generate_fragment_length(rest...);
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

// Retur true if the first argument is less than (i.e. is ordered before) the second
bool str_casei_cmp(std::string_view left, std::string_view right)
{
    auto n = std::min(left.size(), right.size());
    for (std::size_t i = 0; i < n; ++i) {
        auto lc = ddwaf::tolower(left[i]);
        auto rc = ddwaf::tolower(right[i]);
        if (lc != rc) {
            return lc < rc;
        }
    }
    return left.size() <= right.size();
}

void normalize_string(std::string_view key, std::string &buffer, bool trailing_separator)
{
    // Clear should not deallocate...
    // TODO: verify
    buffer.clear();

    if (buffer.capacity() < key.size()) {
        // Add space for the extra comma, just in case
        buffer.reserve(key.size() + 1);
    }

    for (auto c : key) {
        if (c == ',') {
            buffer.append(R"(\,)");
        } else {
            buffer.append(1, ddwaf::tolower(c));
        }
    }

    if (trailing_separator) {
        buffer.append(1, ',');
    }
}

void string_hash_field::operator()(string_buffer &output)
{
    if (value.empty()) {
        return;
    }

    cow_string value_lc{value};
    transformer::lowercase::transform(value_lc);

    sha256_hash hasher;
    hasher << static_cast<std::string_view>(value_lc);

    hasher.write_digest(output.subspan<8>());
}

void key_hash_field::operator()(string_buffer &output)
{
    if (value.type != DDWAF_OBJ_MAP or value.nbEntries == 0) {
        return;
    }

    std::vector<std::string_view> keys;
    keys.reserve(value.nbEntries);

    for (unsigned i = 0; i < value.nbEntries; ++i) {
        const auto &child = value.array[i];

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        keys.emplace_back(key);
    }

    std::sort(keys.begin(), keys.end(), str_casei_cmp);

    sha256_hash hasher;
    std::string normalized;
    for (unsigned i = 0; i < keys.size(); ++i) {
        normalize_string(keys[i], normalized, (i + 1) < keys.size());
        hasher << normalized;
    }

    hasher.write_digest(output.subspan<8>());
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> http_endpoint_fingerprint::eval_impl(
    const unary_argument<std::string_view> &method, const unary_argument<std::string_view> &uri_raw,
    const unary_argument<const ddwaf_object *> &query,
    const unary_argument<const ddwaf_object *> &body, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    // Strip query parameter from raw URI
    auto stripped_uri = uri_raw.value;
    auto query_idx = stripped_uri.find_first_of('?');
    if (query_idx != std::string_view::npos) {
        stripped_uri = stripped_uri.substr(0, query_idx);
    }

    auto res = generate_fragment("http", string_field{method.value},
        string_hash_field{stripped_uri}, key_hash_field{*query.value}, key_hash_field{*body.value});

    return {res, object_store::attribute::none};
}

} // namespace ddwaf
