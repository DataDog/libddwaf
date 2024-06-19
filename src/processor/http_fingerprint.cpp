// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "processor/http_fingerprint.hpp"

#include "sha256.hpp"

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

    void append(std::string_view str)
    {
        memcpy(&buffer[index], str.data(), str.size());
        index += str.size();
    }

    void append_lowercase(std::string_view str)
    {
        for (auto c : str) { buffer[index++] = ddwaf::tolower(c); }
    }

    void append(char c) { buffer[index++] = c; }

    char *move()
    {
        auto *ptr = buffer;
        buffer = nullptr;
        return ptr;
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
    return hasher.digest();
}

} // namespace

std::pair<ddwaf_object, object_store::attribute> http_fingerprint::eval_impl(
    const unary_argument<std::string_view> &method, const unary_argument<std::string_view> &uri_raw,
    const unary_argument<const ddwaf_object *> & /*body*/,
    const unary_argument<const ddwaf_object *> & /*query*/, ddwaf::timer & /*deadline*/) const
{
    // http-<method>-<uri hash>-<body hash>-<query hash>
    string_buffer buffer{4 + 1 + method.value.size() + 1 + 8 + 1 + 8 + 1 + 8};
    buffer.append("http-");
    buffer.append_lowercase(method.value);
    buffer.append('-');

    auto uri_hash = get_truncated_hash(uri_raw.value);
    buffer.append(uri_hash.substr(0, 8));
    buffer.append('-');
    buffer.append("e3b0c442");
    buffer.append('-');
    buffer.append("e3b0c442");

    ddwaf_object res;
    ddwaf_object_stringl_nc(&res, buffer.move(), buffer.length);
    return {res, object_store::attribute::none};
}

} // namespace ddwaf
