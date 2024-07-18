// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "processor/fingerprint.hpp"
#include "ddwaf.h"
#include "sha256.hpp"
#include "transformer/lowercase.hpp"
#include "utils.hpp"

#include <stdexcept>

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

    template <std::size_t N>
    [[nodiscard]] std::span<char, N> subspan()
        requires(N > 0)
    {
        if ((index + N - 1) >= length) {
            throw std::out_of_range("span[index, N) beyond buffer limit");
        }

        std::span<char, N> res{&buffer[index], N};
        index += N;
        return res;
    }

    void append(std::string_view str)
    {
        if (str.empty()) {
            return;
        }

        if ((index + str.length() - 1) >= length) {
            throw std::out_of_range("appending string beyond buffer limit");
        }
        memcpy(&buffer[index], str.data(), str.size());
        index += str.size();
    }

    void append_lowercase(std::string_view str)
    {
        if (str.empty()) {
            return;
        }

        if ((index + str.length() - 1) >= length) {
            throw std::out_of_range("appending string beyond buffer limit");
        }

        for (auto c : str) { buffer[index++] = ddwaf::tolower(c); }
    }

    template <std::size_t N>
    void append(std::array<char, N> str)
        requires(N > 0)
    {
        append(std::string_view{str.data(), N});
    }

    template <std::size_t N>
    void append_lowercase(std::array<char, N> str)
        requires(N > 0)
    {
        append_lowercase(std::string_view{str.data(), N});
    }

    void append(char c) { append(std::string_view{&c, 1}); }

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

struct unsigned_field : field_generator {
    template <typename T>
    explicit unsigned_field(T input)
        requires std::is_unsigned_v<T>
        : value(ddwaf::to_string<std::string>(input))
    {}
    ~unsigned_field() override = default;
    unsigned_field(const unsigned_field &) = default;
    unsigned_field(unsigned_field &&) = default;
    unsigned_field &operator=(const unsigned_field &) = default;
    unsigned_field &operator=(unsigned_field &&) = default;

    std::size_t length() override { return value.size(); }
    void operator()(string_buffer &output) override { output.append(value); }

    std::string value;
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

    std::size_t length() override
    {
        return value.type == DDWAF_OBJ_MAP && value.nbEntries > 0 ? 8 : 0;
    }
    void operator()(string_buffer &output) override;

    ddwaf_object value;
};

struct vector_hash_field : field_generator {
    explicit vector_hash_field(const std::vector<std::string> &input) : value(input) {}
    ~vector_hash_field() override = default;
    vector_hash_field(const vector_hash_field &) = default;
    vector_hash_field(vector_hash_field &&) = default;
    vector_hash_field &operator=(const vector_hash_field &) = delete;
    vector_hash_field &operator=(vector_hash_field &&) = delete;

    std::size_t length() override { return value.empty() ? 0 : 8; }
    void operator()(string_buffer &output) override;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const std::vector<std::string> &value;
};

// This particular generator generates multiple fields (hence the fields name)
// This is to prevent having to create intermediate structures for key and value
// when both have to be processed together. This generator also includes the
// relevant separator, whether the map is empty or not.
struct kv_hash_fields : field_generator {
    explicit kv_hash_fields(const ddwaf_object &input) : value(input) {}
    ~kv_hash_fields() override = default;
    kv_hash_fields(const kv_hash_fields &) = default;
    kv_hash_fields(kv_hash_fields &&) = default;
    kv_hash_fields &operator=(const kv_hash_fields &) = default;
    kv_hash_fields &operator=(kv_hash_fields &&) = default;

    std::size_t length() override
    {
        return value.type == DDWAF_OBJ_MAP && value.nbEntries > 0 ? (8 + 1 + 8) : 1;
    }
    void operator()(string_buffer &output) override;

    ddwaf_object value;
};

template <typename... Generators> std::size_t generate_fragment_length(Generators &...generators)
{
    static_assert(sizeof...(generators) > 0, "At least one generator is required");
    return (generators.length() + ...) + sizeof...(generators) - 1;
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

template <typename... Generators>
ddwaf_object generate_fragment(std::string_view header, Generators... generators)
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

// Return true if the first argument is less than (i.e. is ordered before) the second
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
    return left.size() < right.size();
}

// Default key normalization implies:
// - Lowercasing the string
// - Escaping commas
// - Adding trailing commas
void normalize_key(std::string_view key, std::string &buffer, bool trailing_separator)
{
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

// Header normalization implies:
// - Lowercasing the header
// - Replacing '_' with '-'
void normalize_header(std::string_view original, std::string &buffer)
{
    buffer.resize(original.size());

    for (std::size_t i = 0; i < original.size(); ++i) {
        const auto c = original[i];
        buffer[i] = c == '_' ? '-' : ddwaf::tolower(c);
    }
}

// Value (as opposed to key) normalisation only requires escaping commas
void normalize_value(std::string_view key, std::string &buffer, bool trailing_separator)
{
    buffer.clear();

    if (buffer.capacity() < key.size()) {
        // Add space for the extra comma, just in case
        buffer.reserve(key.size() + 1);
    }

    for (std::size_t i = 0; i < key.size(); ++i) {
        auto comma_idx = key.find(',', i);
        if (comma_idx != std::string_view::npos) {
            if (comma_idx != i) {
                buffer.append(key.substr(i, comma_idx - i));
            }
            buffer.append(R"(\,)");
            i = comma_idx;
        } else {
            buffer.append(key.substr(i));
            break;
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
    if (value.type != DDWAF_OBJ_MAP || value.nbEntries == 0) {
        return;
    }

    std::vector<std::string_view> keys;
    keys.reserve(value.nbEntries);

    std::size_t max_string_size = 0;
    for (unsigned i = 0; i < value.nbEntries; ++i) {
        const auto &child = value.array[i];

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        if (max_string_size > key.size()) {
            max_string_size = key.size();
        }

        keys.emplace_back(key);
    }

    std::sort(keys.begin(), keys.end(), str_casei_cmp);

    sha256_hash hasher;
    std::string normalized;
    // By reserving the largest possible size, it should reduce reallocations
    // We also add +1 to account for the trailing comma
    normalized.reserve(max_string_size + 1);
    for (unsigned i = 0; i < keys.size(); ++i) {
        bool trailing_comma = ((i + 1) < keys.size());
        normalize_key(keys[i], normalized, trailing_comma);
        hasher << normalized;
    }

    hasher.write_digest(output.subspan<8>());
}

void vector_hash_field::operator()(string_buffer &output)
{
    if (value.empty()) {
        return;
    }

    sha256_hash hasher;
    for (unsigned i = 0; i < value.size(); ++i) {
        hasher << value[i];
        if ((i + 1) < value.size()) {
            hasher << ",";
        }
    }
    hasher.write_digest(output.subspan<8>());
}

void kv_hash_fields::operator()(string_buffer &output)
{
    if (value.nbEntries == 0) {
        output.append('-');
        return;
    }

    std::vector<std::pair<std::string_view, std::string_view>> kv_sorted;
    kv_sorted.reserve(value.nbEntries);

    std::size_t max_string_size = 0;
    for (std::size_t i = 0; i < value.nbEntries; ++i) {
        const auto &child = value.array[i];

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        std::string_view val;
        if (child.type == DDWAF_OBJ_STRING) {
            val = std::string_view{child.stringValue, static_cast<std::size_t>(child.nbEntries)};
        }

        auto larger_size = std::max(key.size(), val.size());
        if (max_string_size < larger_size) {
            max_string_size = larger_size;
        }

        kv_sorted.emplace_back(key, val);
    }

    std::sort(kv_sorted.begin(), kv_sorted.end(),
        [](auto &left, auto &right) { return str_casei_cmp(left.first, right.first); });

    sha256_hash key_hasher;
    sha256_hash val_hasher;

    std::string normalized;
    // By reserving the largest possible size, it should reduce reallocations
    // We also add +1 to account for the trailing comma
    normalized.reserve(max_string_size + 1);
    for (unsigned i = 0; i < kv_sorted.size(); ++i) {
        auto [key, val] = kv_sorted[i];

        bool trailing_comma = ((i + 1) < kv_sorted.size());

        normalize_key(key, normalized, trailing_comma);
        key_hasher << normalized;

        normalize_value(val, normalized, trailing_comma);
        val_hasher << normalized;
    }

    key_hasher.write_digest(output.subspan<8>());
    output.append('-');
    val_hasher.write_digest(output.subspan<8>());
}

enum class header_type { unknown, standard, ip_origin, user_agent, datadog };

constexpr std::size_t standard_headers_length = 10;
constexpr std::size_t ip_origin_headers_length = 10;

std::pair<header_type, unsigned> get_header_type_and_index(std::string_view header)
{
    static std::unordered_map<std::string_view, std::pair<header_type, unsigned>> headers{
        {"referer", {header_type::standard, 0}}, {"connection", {header_type::standard, 1}},
        {"accept-encoding", {header_type::standard, 2}},
        {"content-encoding", {header_type::standard, 3}},
        {"cache-control", {header_type::standard, 4}}, {"te", {header_type::standard, 5}},
        {"accept-charset", {header_type::standard, 6}},
        {"content-type", {header_type::standard, 7}}, {"accept", {header_type::standard, 8}},
        {"accept-language", {header_type::standard, 9}},
        {"x-forwarded-for", {header_type::ip_origin, 0}},
        {"x-real-ip", {header_type::ip_origin, 1}}, {"true-client-ip", {header_type::ip_origin, 2}},
        {"x-client-ip", {header_type::ip_origin, 3}}, {"x-forwarded", {header_type::ip_origin, 4}},
        {"forwarded-for", {header_type::ip_origin, 5}},
        {"x-cluster-client-ip", {header_type::ip_origin, 6}},
        {"fastly-client-ip", {header_type::ip_origin, 7}},
        {"cf-connecting-ip", {header_type::ip_origin, 8}},
        {"cf-connecting-ipv6", {header_type::ip_origin, 9}},
        {"user-agent", {header_type::user_agent, 0}}};

    if (header.starts_with("x-datadog")) {
        return {header_type::datadog, 0};
    }

    auto it = headers.find(header);
    if (it == headers.end()) {
        return {header_type::unknown, 0};
    }
    return it->second;
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
    auto query_or_frag_idx = stripped_uri.find_first_of("?#");
    if (query_or_frag_idx != std::string_view::npos) {
        stripped_uri = stripped_uri.substr(0, query_or_frag_idx);
    }

    ddwaf_object res;
    ddwaf_object_invalid(&res);
    try {
        res = generate_fragment("http", string_field{method.value}, string_hash_field{stripped_uri},
            key_hash_field{*query.value}, key_hash_field{*body.value});
    } catch (const std::out_of_range &e) {
        DDWAF_WARN("Failed to generate http endpoint fingerprint: {}", e.what());
    }

    return {res, object_store::attribute::none};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> http_header_fingerprint::eval_impl(
    const unary_argument<const ddwaf_object *> &headers, ddwaf::timer &deadline) const
{
    std::string known_header_bitset;
    known_header_bitset.resize(standard_headers_length, '0');

    std::string_view user_agent;
    std::vector<std::string> unknown_headers;
    std::string normalized_header;
    for (std::size_t i = 0; i < headers.value->nbEntries; ++i) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto &child = headers.value->array[i];
        std::string_view header{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        normalize_header(header, normalized_header);
        auto [type, index] = get_header_type_and_index(normalized_header);
        if (type == header_type::standard) {
            known_header_bitset[index] = '1';
        } else if (type == header_type::unknown) {
            unknown_headers.emplace_back(normalized_header);
        } else if (type == header_type::user_agent && child.type == DDWAF_OBJ_STRING) {
            user_agent = {child.stringValue, static_cast<std::size_t>(child.nbEntries)};
        }
    }
    std::sort(unknown_headers.begin(), unknown_headers.end());

    auto res =
        generate_fragment("hdr", string_field{known_header_bitset}, string_hash_field{user_agent},
            unsigned_field{unknown_headers.size()}, vector_hash_field{unknown_headers});

    return {res, object_store::attribute::none};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> http_network_fingerprint::eval_impl(
    const unary_argument<const ddwaf_object *> &headers, ddwaf::timer &deadline) const
{
    std::string ip_origin_bitset;
    ip_origin_bitset.resize(ip_origin_headers_length, '0');

    unsigned chosen_header = ip_origin_headers_length;
    std::string_view chosen_header_value;
    std::string normalized_header;
    for (std::size_t i = 0; i < headers.value->nbEntries; ++i) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto &child = headers.value->array[i];

        std::string_view header{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        normalize_header(header, normalized_header);
        auto [type, index] = get_header_type_and_index(normalized_header);
        if (type == header_type::ip_origin) {
            ip_origin_bitset[index] = '1';
            // Verify not only precedence but also type, as a header of an unexpected
            // type will be unlikely to be used unless the framework has somehow
            // broken down the header into constituent IPs
            if (chosen_header > index && child.type == DDWAF_OBJ_STRING) {
                chosen_header_value = {
                    child.stringValue, static_cast<std::size_t>(child.nbEntries)};
                chosen_header = index;
            }
        }
    }

    unsigned ip_count = 0;
    if (!chosen_header_value.empty()) {
        // For now, count commas
        ++ip_count;
        for (auto c : chosen_header_value) { ip_count += static_cast<unsigned int>(c == ','); }
    }

    auto res = generate_fragment("net", unsigned_field{ip_count}, string_field{ip_origin_bitset});

    return {res, object_store::attribute::none};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> session_fingerprint::eval_impl(
    const unary_argument<const ddwaf_object *> &cookies,
    const unary_argument<std::string_view> &session_id,
    const unary_argument<std::string_view> &user_id, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    auto res = generate_fragment("ssn", string_hash_field{user_id.value},
        kv_hash_fields{*cookies.value}, string_hash_field{session_id.value});
    return {res, object_store::attribute::none};
}

} // namespace ddwaf
