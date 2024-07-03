// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "processor/http_fingerprint.hpp"

#include "sha256.hpp"
#include "transformer/lowercase.hpp"

namespace ddwaf {

namespace {

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

// TODO write this directly into string buffer
std::string get_truncated_hash(std::string_view str)
{
    sha256_hash hasher;
    hasher << str;
    return hasher.digest().substr(0, 8);
}

std::string get_truncated_hash(const ddwaf_object &body)
{
    if (body.type != DDWAF_OBJ_MAP or body.nbEntries == 0) {
        return "";
    }

    std::vector<char *> lc_key_buffer;
    lc_key_buffer.reserve(body.nbEntries);

    scope_exit free_ptrs_at_exit([&lc_key_buffer]() {
        for (auto *ptr : lc_key_buffer) {
            // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
            free(ptr);
        }
    });
    std::vector<std::string_view> keys;
    keys.reserve(body.nbEntries);

    for (unsigned i = 0; i < body.nbEntries; ++i) {
        const auto &child = body.array[i];

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        cow_string lc_key{key};

        if (transformer::lowercase::transform(lc_key)) {
            auto [ptr, size] = lc_key.move();
            lc_key_buffer.emplace_back(ptr);
            keys.emplace_back(ptr, size);
        } else {
            keys.emplace_back(key);
        }
    }

    std::sort(keys.begin(), keys.end());

    sha256_hash hasher;
    for (auto key : keys) { hasher << key; }

    return hasher.digest<8>();
}

} // namespace

std::pair<ddwaf_object, object_store::attribute> http_fingerprint::eval_impl(
    const unary_argument<std::string_view> &method, const unary_argument<std::string_view> &uri_raw,
    const unary_argument<const ddwaf_object *> &body,
    const unary_argument<const ddwaf_object *> &query, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    // http-<method>-<uri hash>-<body hash>-<query hash>
    string_buffer buffer{4 + 1 + method.value.size() + 1 + 8 + 1 + 8 + 1 + 8};
    buffer.append("http-");
    buffer.append_lowercase(method.value);
    buffer.append('-');

    buffer.append(get_truncated_hash(uri_raw.value));
    buffer.append('-');
    buffer.append(get_truncated_hash(*body.value));
    buffer.append('-');
    buffer.append(get_truncated_hash(*query.value));

    auto [ptr, size] = buffer.move();
    ddwaf_object res;
    ddwaf_object_stringl_nc(&res, ptr, size);
    return {res, object_store::attribute::none};
}

} // namespace ddwaf
